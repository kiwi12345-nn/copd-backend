import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mqtt from "mqtt";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const MQTT_URL = process.env.MQTT_URL || "mqtt://broker.emqx.io:1883";
const MQTT_TOPIC = process.env.MQTT_TOPIC || "copd/patient1/data";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("THIEU SUPABASE_URL HOAC SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

function toNumber(value, defaultValue = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : defaultValue;
}

function toBooleanReady(value) {
  return value === true || value === 1 || value === "1";
}

function getAlertType(payload) {
  const msg = String(payload.message || payload.alert_message || "").toUpperCase();

  if (msg.includes("SPO2")) return "SpO2";
  if (msg.includes("HR")) return "HR";
  if (msg.includes("RR")) return "RR";
  if (msg.includes("NHIET") || msg.includes("TEMP")) return "Temp";

  return "General";
}

async function saveSensorData(payload) {
  const deviceId = payload.device || payload.device_id || "COPD_01";

  const ready = toBooleanReady(payload.ready);

  const rr = toNumber(payload.rr, 0);
  const hr = toNumber(payload.hr, 0);
  const spo2 = toNumber(payload.spo2, 0);
  const temperature = toNumber(payload.temp ?? payload.temperature, 0);

  const flexRaw = toNumber(payload.flex_raw, 0);
  const flexFiltered = toNumber(payload.flex_filtered, 0);
  const flexBaseline = toNumber(payload.flex_baseline, 0);
  const flexDelta = toNumber(payload.flex_delta, 0);

  const alertLevel = toNumber(payload.alert ?? payload.alert_level, 0);
  const alertMessage = payload.message || payload.alert_message || "";

  await supabase.from("devices").upsert(
    {
      device_id: deviceId,
      patient_id: "P001",
      device_name: "ESP32-S3 COPD Monitor",
      online: true,
      last_seen_at: new Date().toISOString()
    },
    {
      onConflict: "device_id"
    }
  );

  const row = {
    device_id: deviceId,
    ready,
    rr,
    hr,
    spo2,
    temperature,
    flex_raw: flexRaw,
    flex_filtered: flexFiltered,
    flex_baseline: flexBaseline,
    flex_delta: flexDelta,
    alert_level: alertLevel,
    alert_message: alertMessage,
    raw_payload: payload
  };

  const { error } = await supabase.from("sensor_data").insert(row);

  if (error) {
    console.error("LOI LUU sensor_data:", error.message);
    return;
  }

  console.log("DA LUU DATA:", {
    deviceId,
    ready,
    rr,
    hr,
    spo2,
    temperature,
    alertLevel
  });

  if (ready && alertLevel > 0) {
    const alertType = getAlertType(payload);

    const { error: alertError } = await supabase.from("alerts_log").insert({
      device_id: deviceId,
      alert_level: alertLevel,
      alert_type: alertType,
      alert_value: 0,
      threshold_value: 0,
      message: alertMessage || "CANH BAO TU THIET BI"
    });

    if (alertError) {
      console.error("LOI LUU alerts_log:", alertError.message);
    }
  }
}

// =====================================================
// MQTT CLIENT
// =====================================================
const mqttClientId = `copd_backend_${Math.random().toString(16).slice(2)}`;

const mqttClient = mqtt.connect(MQTT_URL, {
  clientId: mqttClientId,
  clean: true,
  reconnectPeriod: 5000,
  connectTimeout: 10000
});

mqttClient.on("connect", () => {
  console.log("MQTT CONNECTED:", MQTT_URL);

  mqttClient.subscribe(MQTT_TOPIC, { qos: 0 }, (err) => {
    if (err) {
      console.error("LOI SUBSCRIBE MQTT:", err.message);
    } else {
      console.log("DA SUBSCRIBE TOPIC:", MQTT_TOPIC);
    }
  });
});

mqttClient.on("message", async (topic, message) => {
  try {
    const text = message.toString();
    const payload = JSON.parse(text);

    console.log("NHAN MQTT:", topic, payload);

    await saveSensorData(payload);
  } catch (err) {
    console.error("LOI XU LY MQTT:", err.message);
  }
});

mqttClient.on("error", (err) => {
  console.error("MQTT ERROR:", err.message);
});

// =====================================================
// API CHO WEB DASHBOARD VA FLUTTER APP
// =====================================================

app.get("/", (req, res) => {
  res.json({
    status: "OK",
    name: "COPD Monitor Backend",
    mqtt_topic: MQTT_TOPIC
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    mqtt_connected: mqttClient.connected,
    time: new Date().toISOString()
  });
});

app.get("/api/latest", async (req, res) => {
  const deviceId = req.query.device_id || "COPD_01";

  const { data, error } = await supabase
    .from("sensor_data")
    .select("*")
    .eq("device_id", deviceId)
    .order("timestamp", { ascending: false })
    .limit(1)
    .single();

  if (error) {
    return res.status(500).json({
      error: error.message
    });
  }

  res.json(data);
});

app.get("/api/history", async (req, res) => {
  const deviceId = req.query.device_id || "COPD_01";
  const limit = Math.min(toNumber(req.query.limit, 100), 500);

  const { data, error } = await supabase
    .from("sensor_data")
    .select("*")
    .eq("device_id", deviceId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (error) {
    return res.status(500).json({
      error: error.message
    });
  }

  res.json(data);
});

app.get("/api/alerts", async (req, res) => {
  const deviceId = req.query.device_id || "COPD_01";
  const limit = Math.min(toNumber(req.query.limit, 50), 200);

  const { data, error } = await supabase
    .from("alerts_log")
    .select("*")
    .eq("device_id", deviceId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (error) {
    return res.status(500).json({
      error: error.message
    });
  }

  res.json(data);
});

app.get("/api/patient", async (req, res) => {
  const patientId = req.query.patient_id || "P001";

  const { data, error } = await supabase
    .from("patients")
    .select("*")
    .eq("patient_id", patientId)
    .single();

  if (error) {
    return res.status(500).json({
      error: error.message
    });
  }

  res.json(data);
});

app.post("/api/fcm/register-token", async (req, res) => {
  const { user_id, fcm_token, device_type } = req.body;

  if (!user_id || !fcm_token) {
    return res.status(400).json({
      error: "Thieu user_id hoac fcm_token"
    });
  }

  const { error } = await supabase.from("fcm_tokens").insert({
    user_id,
    fcm_token,
    device_type: device_type || "android",
    last_active_at: new Date().toISOString()
  });

  if (error) {
    return res.status(500).json({
      error: error.message
    });
  }

  res.json({
    success: true
  });
});

app.listen(PORT, () => {
  console.log(`COPD BACKEND RUNNING ON PORT ${PORT}`);
});