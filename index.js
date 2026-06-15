import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mqtt from "mqtt";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;
const MQTT_URL = process.env.MQTT_URL || "mqtt://broker.emqx.io:1883";
const MQTT_TOPIC = process.env.MQTT_TOPIC || "copd/patient1/data";
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const APP_JWT_SECRET = process.env.APP_JWT_SECRET || "COPD_REAL_AUTH_SECRET_CHANGE_THIS_IN_RENDER";

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("THIEU SUPABASE_URL HOAC SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================================
// REAL AUTH ONLY
// Không còn tài khoản demo/fallback.
// Người dùng phải tự đăng ký và dữ liệu được lưu trong Supabase app_users.
// ============================================================

// ============================================================
// HELPERS
// ============================================================
function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signToken(payload) {
  const body = base64url(JSON.stringify(payload));
  const signature = crypto
    .createHmac("sha256", APP_JWT_SECRET)
    .update(body)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${body}.${signature}`;
}

function verifyToken(token) {
  try {
    if (!token || !token.includes(".")) return null;
    const [body, signature] = token.split(".");
    const expectedSignature = crypto
      .createHmac("sha256", APP_JWT_SECRET)
      .update(body)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    if (signature !== expectedSignature) return null;

    const json = Buffer.from(body, "base64").toString("utf8");
    const payload = JSON.parse(json);
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "").trim();
  const tokenUser = verifyToken(token);

  if (!tokenUser) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Bạn chưa đăng nhập hoặc token không hợp lệ",
    });
  }

  // V10 FIX: Token cũ có thể còn patient_id cũ trong trình duyệt.
  // Mỗi request sẽ đọc lại user mới nhất từ Supabase theo user_id/email,
  // nhờ vậy khi sửa patient_id trong database thì app lấy đúng dữ liệu cảm biến.
  try {
    let query = supabase.from("app_users").select("*").eq("active", true);
    if (tokenUser.user_id) {
      query = query.eq("user_id", tokenUser.user_id);
    } else {
      query = query.eq("email", normalizeEmail(tokenUser.email));
    }

    const { data: dbUser, error } = await query.maybeSingle();
    if (!error && dbUser) {
      req.user = await buildSafeUser(dbUser);
      return next();
    }
  } catch (e) {
    console.error("LOI REFRESH USER:", e.message);
  }

  req.user = tokenUser;
  next();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function makeId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

async function nextPatientId() {
  const { data, error } = await supabase.rpc("next_patient_id");
  if (!error && data) return String(data);
  // fallback nếu RPC chưa chạy: vẫn tăng theo thời gian nhưng nên chạy SQL V9 để dùng P0001/P0002
  return `P${Date.now().toString().slice(-7)}`;
}

async function isPasswordAlreadyUsed(password) {
  const { data, error } = await supabase
    .from("app_users")
    .select("password_hash")
    .eq("active", true);
  if (error || !Array.isArray(data)) return false;
  for (const row of data) {
    if (verifyPassword(row.password_hash, password)) return true;
  }
  return false;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.createHash("sha256").update(`${salt}:${password}`).digest("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(storedHash, password) {
  if (!storedHash || !storedHash.includes(":")) return false;
  const [salt, hash] = storedHash.split(":");
  const test = crypto.createHash("sha256").update(`${salt}:${password}`).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(test));
}

function toNumber(value, defaultValue = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : defaultValue;
}

function toBooleanReady(value) {
  return value === true || value === 1 || value === "1";
}

function buildDateRange(dateValue) {
  if (!dateValue) return null;
  const s = String(dateValue).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const start = new Date(`${s}T00:00:00.000Z`);
  const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}


async function hasSensorData(patientId) {
  if (!patientId) return false;
  const { data, error } = await supabase
    .from("sensor_data")
    .select("id")
    .eq("patient_id", String(patientId))
    .order("timestamp", { ascending: false })
    .limit(1);
  return !error && Array.isArray(data) && data.length > 0;
}

async function getLatestSensorPatientId() {
  const { data, error } = await supabase
    .from("sensor_data")
    .select("patient_id")
    .not("patient_id", "is", null)
    .order("timestamp", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!error && data?.patient_id) return String(data.patient_id);
  return "P001";
}


async function getLatestVitalsRow(patientId) {
  const { data, error } = await supabase
    .from("sensor_data")
    .select("*")
    .eq("patient_id", String(patientId))
    .order("timestamp", { ascending: false })
    .limit(300);

  if (error) throw error;
  if (!Array.isArray(data) || data.length === 0) return null;

  const latest = { ...data[0] };
  const latestPositive = (key) => {
    const found = data.find((r) => Number(r[key] ?? 0) > 0);
    return found ? found[key] : latest[key];
  };

  // V11 FIX: sensor_data có thể xen kẽ dòng 0 khi chưa đặt tay MAX.
  // App cần hiển thị kết quả đo hợp lệ gần nhất, không để --- chỉ vì dòng mới nhất là 0.
  latest.rr = latestPositive("rr");
  latest.hr = latestPositive("hr");
  latest.spo2 = latestPositive("spo2");
  latest.temperature = latestPositive("temperature");
  latest.ready = Number(latest.hr || 0) > 0 || Number(latest.spo2 || 0) > 0 || latest.ready === true;
  latest.alert_message = latest.alert_message || "DANG CAP NHAT DU LIEU CAM BIEN";
  return latest;
}

async function resolvePatientIdWithSensorFallback(user, requestedPatientId) {
  const requested = String(requestedPatientId || getDefaultPatientIdForUser(user) || "P001");

  // Nếu bệnh nhân đang chọn đã có dữ liệu cảm biến, dùng đúng bệnh nhân đó.
  if (await hasSensorData(requested)) return requested;

  // Nếu bệnh nhân đang chọn chưa có dữ liệu, dùng bệnh nhân đang có dữ liệu cảm biến mới nhất.
  // Cách này giúp app luôn hiển thị số đo thật từ ESP32 trong mô hình 1 thiết bị thử nghiệm.
  const latestSensorPatient = await getLatestSensorPatientId();
  return latestSensorPatient || requested;
}

function getDefaultPatientIdForUser(user) {
  if (user?.role === "patient") return user.patient_id;
  if (Array.isArray(user?.allowed_patients) && user.allowed_patients.length > 0) {
    return user.allowed_patients[0];
  }
  return "P001";
}

function canAccessPatient(user, patientId) {
  if (!user || !patientId) return false;
  if (["admin", "doctor", "hospital"].includes(user.role)) return true;
  return Array.isArray(user.allowed_patients) && user.allowed_patients.includes(String(patientId));
}

async function getAllowedPatientsForUser(user) {
  if (!user) return [];

  if (user.role === "admin") {
    const { data } = await supabase.from("patients").select("patient_id").limit(200);
    if (Array.isArray(data) && data.length > 0) return data.map((r) => String(r.patient_id));
    return ["P001"];
  }

  if (user.role === "hospital" || user.role === "doctor") {
    if (!user.hospital_id) return ["P001"];
    const { data } = await supabase
      .from("hospital_patient_links")
      .select("patient_id")
      .eq("hospital_id", user.hospital_id)
      .eq("status", "active")
      .limit(300);
    if (Array.isArray(data) && data.length > 0) return data.map((r) => String(r.patient_id));
    return ["P001"];
  }

  if (Array.isArray(user.allowed_patients) && user.allowed_patients.length > 0) {
    return user.allowed_patients.map(String);
  }

  const ownPatientId = user.patient_id ? String(user.patient_id) : null;
  const latestSensorPatient = await getLatestSensorPatientId();

  if (ownPatientId && await hasSensorData(ownPatientId)) {
    return [ownPatientId];
  }

  if (latestSensorPatient) {
    return [latestSensorPatient];
  }

  return ownPatientId ? [ownPatientId] : ["P001"];
}

async function logActivity(user, action, details = {}, patientId = null) {
  try {
    await supabase.from("app_activity_logs").insert({
      user_id: user?.user_id || null,
      email: user?.email || null,
      role: user?.role || null,
      hospital_id: user?.hospital_id || null,
      patient_id: patientId || user?.patient_id || null,
      action,
      details,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error("LOI LUU app_activity_logs:", err.message);
  }
}

async function buildSafeUser(dbUser) {
  const base = {
    user_id: dbUser.user_id,
    email: dbUser.email,
    full_name: dbUser.full_name,
    phone: dbUser.phone || "",
    role: dbUser.role,
    patient_id: dbUser.patient_id || null,
    hospital_id: dbUser.hospital_id || null,
    allowed_patients: Array.isArray(dbUser.allowed_patients) ? dbUser.allowed_patients : [],
  };

  base.allowed_patients = await getAllowedPatientsForUser(base);
  return base;
}

function tokenForUser(safeUser) {
  return signToken({
    ...safeUser,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 7,
  });
}

// ============================================================
// PUBLIC / AUTH API
// ============================================================
app.get("/api/hospitals", async (req, res) => {
  const { data, error } = await supabase
    .from("hospitals")
    .select("hospital_id,hospital_name,address,phone,email,active")
    .eq("active", true)
    .order("hospital_name", { ascending: true });

  if (error) {
    return res.status(500).json({
      error: error.message,
      message: "Không tải được danh sách bệnh viện đã đăng ký"
    });
  }

  res.json(Array.isArray(data) ? data : []);
});

app.post("/api/auth/register", async (req, res) => {
  const body = req.body || {};
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const fullName = String(body.full_name || "").trim();
  const phone = String(body.phone || "").trim();
  const role = String(body.role || "patient").trim();
  const allowedRoles = ["patient", "family", "doctor", "hospital", "admin"];

  if (!email || !password || password.length < 6 || !fullName) {
    return res.status(400).json({
      error: "MISSING_FIELDS",
      message: "Cần nhập họ tên, email và mật khẩu tối thiểu 6 ký tự",
    });
  }

  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: "INVALID_ROLE", message: "Vai trò không hợp lệ" });
  }

  const { data: existed } = await supabase
    .from("app_users")
    .select("email")
    .eq("email", email)
    .maybeSingle();

  if (existed) {
    return res.status(409).json({ error: "EMAIL_EXISTS", message: "Email này đã được đăng ký" });
  }

  const passwordDuplicated = await isPasswordAlreadyUsed(password);
  if (passwordDuplicated) {
    return res.status(409).json({
      error: "PASSWORD_ALREADY_USED",
      message: "Mật khẩu này đã được tài khoản khác sử dụng. Vui lòng tạo mật khẩu khác để tránh trùng lặp."
    });
  }

  let hospitalId = body.hospital_id ? String(body.hospital_id).trim() : null;
  let patientId = body.patient_id ? String(body.patient_id).trim() : null;
  const dateOfBirth = body.date_of_birth ? String(body.date_of_birth).trim() : null;
  const age = body.age !== undefined && body.age !== null && String(body.age).trim() !== "" ? toNumber(body.age, null) : null;
  let allowedPatients = [];

  if (role === "hospital") {
    hospitalId = `H${Date.now().toString().slice(-7)}`;
    const hospitalName = String(body.hospital_name || fullName).trim();
    const { error: hospitalError } = await supabase.from("hospitals").insert({
      hospital_id: hospitalId,
      hospital_name: hospitalName,
      address: String(body.address || "Tư vấn online"),
      phone,
      email,
      active: true,
      created_at: new Date().toISOString(),
    });
    if (hospitalError) return res.status(500).json({ error: hospitalError.message });
  }

  if (["patient", "family", "doctor"].includes(role) && !hospitalId) {
    return res.status(400).json({
      error: "MISSING_HOSPITAL",
      message: "Cần chọn bệnh viện đã đăng ký trên hệ thống",
    });
  }

  if (role === "patient") {
    // V9: bệnh nhân không nhập ID thủ công nữa. Hệ thống tự cấp P0001, P0002...
    patientId = await nextPatientId();
    allowedPatients = [patientId];

    await supabase.from("patients").upsert(
      {
        patient_id: patientId,
        full_name: fullName,
        phone,
        hospital_id: hospitalId,
        date_of_birth: dateOfBirth,
        age,
        diagnosis: "COPD cần theo dõi hô hấp",
        created_at: new Date().toISOString(),
      },
      { onConflict: "patient_id" }
    );

    await supabase.from("hospital_patient_links").upsert(
      {
        hospital_id: hospitalId,
        patient_id: patientId,
        status: "active",
        created_at: new Date().toISOString(),
      },
      { onConflict: "hospital_id,patient_id" }
    );
  }

  if (role === "family") {
    if (!patientId) {
      return res.status(400).json({
        error: "MISSING_PATIENT_ID",
        message: "Người nhà cần nhập mã bệnh nhân cần theo dõi"
      });
    }

    const { data: linkedPatient } = await supabase
      .from("hospital_patient_links")
      .select("patient_id")
      .eq("hospital_id", hospitalId)
      .eq("patient_id", patientId)
      .eq("status", "active")
      .maybeSingle();

    if (!linkedPatient) {
      return res.status(404).json({
        error: "PATIENT_NOT_FOUND_IN_HOSPITAL",
        message: "Không tìm thấy mã bệnh nhân này trong bệnh viện đã chọn"
      });
    }

    allowedPatients = [patientId];
  }

  if (role === "doctor") {
    allowedPatients = [];
    const doctorId = `D${Date.now().toString().slice(-7)}`;
    const { data: hospital } = await supabase
      .from("hospitals")
      .select("hospital_name")
      .eq("hospital_id", hospitalId)
      .maybeSingle();

    await supabase.from("doctors").insert({
      doctor_id: doctorId,
      hospital_id: hospitalId,
      full_name: fullName,
      specialty: String(body.specialty || "Hô hấp - COPD"),
      hospital: hospital?.hospital_name || "Bệnh viện đã đăng ký",
      experience_years: toNumber(body.experience_years, 0),
      price: toNumber(body.price, 0),
      location: "Tư vấn online",
      rating: 5,
    });
  }

  if (role === "admin" || role === "hospital") {
    allowedPatients = [];
  }

  const userRow = {
    user_id: makeId("U"),
    email,
    password_hash: hashPassword(password),
    full_name: fullName,
    phone,
    role,
    date_of_birth: role === "patient" ? dateOfBirth : null,
    age: role === "patient" ? age : null,
    patient_id: patientId,
    hospital_id: hospitalId,
    allowed_patients: allowedPatients,
    active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const { data, error } = await supabase.from("app_users").insert(userRow).select("*").single();
  if (error) return res.status(500).json({ error: error.message });

  const safeUser = await buildSafeUser(data);
  await logActivity(safeUser, "REGISTER", { role, hospital_id: hospitalId }, patientId);

  res.json({ token: tokenForUser(safeUser), user: safeUser, message: "Đăng ký thành công" });
});

app.post("/api/auth/login", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");

  const { data: dbUser, error } = await supabase
    .from("app_users")
    .select("*")
    .eq("email", email)
    .eq("active", true)
    .maybeSingle();

  if (!error && dbUser) {
    if (!verifyPassword(dbUser.password_hash, password)) {
      return res.status(401).json({ error: "LOGIN_FAILED", message: "Email hoặc mật khẩu không đúng" });
    }

    const safeUser = await buildSafeUser(dbUser);
    await logActivity(safeUser, "LOGIN", { source: "app_users" }, safeUser.patient_id);
    return res.json({ token: tokenForUser(safeUser), user: safeUser });
  }

  return res.status(401).json({
    error: "LOGIN_FAILED",
    message: "Email hoặc mật khẩu không đúng hoặc tài khoản chưa được đăng ký"
  });
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: req.user }));

// ============================================================
// PATIENT / HOSPITAL ACCESS API
// ============================================================
app.get("/api/my/patients", requireAuth, async (req, res) => {
  const allowed = await getAllowedPatientsForUser(req.user);

  if (allowed.length === 0) return res.json([]);

  const { data, error } = await supabase
    .from("patients")
    .select("*")
    .in("patient_id", allowed)
    .order("patient_id", { ascending: true });

  if (error) {
    return res.json(
      allowed.map((id) => ({
        patient_id: id,
        full_name: id === "P001" ? "Bệnh nhân P001" : `Bệnh nhân ${id}`,
        diagnosis: "COPD cần theo dõi hô hấp",
        hospital_id: req.user.hospital_id || "H001",
      }))
    );
  }

  const rows = Array.isArray(data) ? data : [];
  const merged = allowed.map((patientId) => {
    const found = rows.find((r) => String(r.patient_id) === String(patientId));
    return found || {
      patient_id: patientId,
      full_name: patientId === "P001" ? "Bệnh nhân P001" : `Bệnh nhân ${patientId}`,
      gender: "---",
      age: null,
      diagnosis: "COPD cần theo dõi hô hấp",
      phone: "---",
      address: "---",
      hospital_id: req.user.hospital_id || "H001",
    };
  });

  res.json(merged);
});

app.get("/api/patient/full", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user));
  if (!canAccessPatient(req.user, patientId)) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem bệnh nhân này" });
  }

  const [profile, latest, history, alerts, appointments] = await Promise.all([
    supabase.from("patients").select("*").eq("patient_id", patientId).maybeSingle(),
    supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(1).maybeSingle(),
    supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(80),
    supabase.from("alerts_log").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(30),
    supabase.from("doctor_appointments").select("*").eq("patient_id", patientId).order("appointment_date", { ascending: true }).order("appointment_time", { ascending: true }).limit(50),
  ]);

  res.json({
    profile: profile.data || null,
    latest: latest.data || null,
    history: Array.isArray(history.data) ? history.data : [],
    alerts: Array.isArray(alerts.data) ? alerts.data : [],
    appointments: Array.isArray(appointments.data) ? appointments.data : [],
  });
});

// ============================================================
// APPOINTMENTS / DOCTORS
// ============================================================
function canManageAppointments(user) {
  return user && ["admin", "doctor", "hospital"].includes(user.role);
}

app.get("/api/doctors", requireAuth, async (req, res) => {
  let query = supabase
    .from("doctors")
    .select("*")
    .order("full_name", { ascending: true });

  if (["patient", "family", "doctor", "hospital"].includes(req.user.role) && req.user.hospital_id) {
    query = query.eq("hospital_id", req.user.hospital_id);
  }

  const { data, error } = await query;
  if (error || !Array.isArray(data) || data.length === 0) {
    return res.json([
      {
        doctor_id: "D001",
        hospital_id: req.user.hospital_id || "H001",
        full_name: "BS. Hô hấp COPD",
        specialty: "Hô hấp - COPD",
        hospital: "Bệnh viện đã đăng ký",
        experience_years: 8,
        price: 150000,
        location: "Tư vấn online",
        rating: 4.8,
      },
    ]);
  }
  res.json(data);
});

app.post("/api/my/appointments", requireAuth, async (req, res) => {
  const body = req.body || {};
  const doctorId = String(body.doctor_id || "D001");
  const appointmentDate = String(body.appointment_date || "").trim();
  const appointmentTime = String(body.appointment_time || "").trim();
  const reason = String(body.reason || "Tái khám COPD định kỳ").trim();
  const patientId = String(body.patient_id || getDefaultPatientIdForUser(req.user) || "P001");

  if (!canAccessPatient(req.user, patientId)) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền đặt lịch cho bệnh nhân này" });
  }
  if (!appointmentDate || !appointmentTime) {
    return res.status(400).json({ error: "MISSING_FIELDS", message: "Thiếu ngày hoặc khung giờ khám" });
  }

  const { data: doctor } = await supabase
    .from("doctors")
    .select("doctor_id,hospital_id,full_name")
    .eq("doctor_id", doctorId)
    .maybeSingle();

  const hospitalId = doctor?.hospital_id || req.user.hospital_id || "H001";

  const { data: lastRows, error: queueError } = await supabase
    .from("doctor_appointments")
    .select("queue_number")
    .eq("doctor_id", doctorId)
    .eq("appointment_date", appointmentDate)
    .eq("appointment_time", appointmentTime)
    .order("queue_number", { ascending: false })
    .limit(1);

  if (queueError) return res.status(500).json({ error: queueError.message });

  const lastQueue = Array.isArray(lastRows) && lastRows.length > 0 ? Number(lastRows[0].queue_number || 0) : 0;

  const row = {
    doctor_id: doctorId,
    hospital_id: hospitalId,
    patient_id: patientId,
    patient_name: body.patient_name || req.user.full_name || patientId,
    requester_user_id: req.user.user_id,
    requester_name: req.user.full_name,
    requester_role: req.user.role,
    appointment_date: appointmentDate,
    appointment_time: appointmentTime,
    queue_number: lastQueue + 1,
    reason,
    status: "pending",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const { data, error } = await supabase.from("doctor_appointments").insert(row).select("*").single();
  if (error) return res.status(500).json({ error: error.message });

  await logActivity(req.user, "CREATE_APPOINTMENT", { appointment_id: data.appointment_id, doctor_id: doctorId, appointment_date: appointmentDate, appointment_time: appointmentTime }, patientId);

  res.json({
    success: true,
    appointment: data,
    message: `Đã đặt lịch. Số thứ tự trong khung ${appointmentTime} là ${data.queue_number}`,
  });
});

app.get("/api/my/appointments", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "P001");
  if (!canAccessPatient(req.user, patientId)) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem lịch của bệnh nhân này" });
  }
  const { data, error } = await supabase
    .from("doctor_appointments")
    .select("*")
    .eq("patient_id", patientId)
    .order("appointment_date", { ascending: true })
    .order("appointment_time", { ascending: true })
    .order("queue_number", { ascending: true })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

app.get("/api/doctor/appointments", requireAuth, async (req, res) => {
  if (!canManageAppointments(req.user)) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ/bệnh viện/admin được xem danh sách lịch hẹn" });
  }

  const status = String(req.query.status || "").trim();
  let query = supabase
    .from("doctor_appointments")
    .select("*")
    .order("appointment_date", { ascending: true })
    .order("appointment_time", { ascending: true })
    .order("queue_number", { ascending: true });

  if (req.user.role !== "admin" && req.user.hospital_id) {
    query = query.eq("hospital_id", req.user.hospital_id);
  }
  if (status) query = query.eq("status", status);

  const { data, error } = await query.limit(300);
  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

app.patch("/api/doctor/appointments/:id/status", requireAuth, async (req, res) => {
  if (!canManageAppointments(req.user)) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ/bệnh viện/admin được cập nhật lịch hẹn" });
  }

  const status = String(req.body?.status || "").trim();
  const allowed = ["pending", "confirmed", "done", "cancelled"];
  if (!allowed.includes(status)) return res.status(400).json({ error: "INVALID_STATUS", message: "Trạng thái không hợp lệ" });

  const { data, error } = await supabase
    .from("doctor_appointments")
    .update({ status, updated_at: new Date().toISOString() })
    .eq("appointment_id", req.params.id)
    .select("*")
    .single();

  if (error) return res.status(500).json({ error: error.message });

  await logActivity(req.user, "UPDATE_APPOINTMENT_STATUS", { appointment_id: req.params.id, status }, data.patient_id);
  res.json({ success: true, appointment: data });
});

// ============================================================
// SENSOR / ALERT / SOS API CHO APP
// ============================================================
app.get("/api/my/latest", requireAuth, async (req, res) => {
  const requestedPatientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "P001");
  const patientId = await resolvePatientIdWithSensorFallback(req.user, requestedPatientId);

  try {
    const data = await getLatestVitalsRow(patientId);
    return res.json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/my/history", requireAuth, async (req, res) => {
  const requestedPatientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "P001");
  const patientId = await resolvePatientIdWithSensorFallback(req.user, requestedPatientId);
  const limit = Math.min(Number(req.query.limit || 80), 500);
  const dateRange = buildDateRange(req.query.date);

  let query = supabase
    .from("sensor_data")
    .select("*")
    .eq("patient_id", patientId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (dateRange) {
    query = query.gte("timestamp", dateRange.start).lt("timestamp", dateRange.end);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  if (String(req.query.track || "") === "1") {
    await logActivity(req.user, "VIEW_MEASUREMENT_HISTORY", {
      patient_id: patientId,
      date: req.query.date || "latest",
      count: Array.isArray(data) ? data.length : 0,
    }, patientId);
  }

  res.json(Array.isArray(data) ? data : []);
});

app.get("/api/my/alerts", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user));
  const limit = Math.min(Number(req.query.limit || 50), 200);
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem cảnh báo bệnh nhân này" });

  const { data, error } = await supabase
    .from("alerts_log")
    .select("*")
    .eq("patient_id", patientId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

app.post("/api/my/sos", requireAuth, async (req, res) => {
  const patientId = String(req.body?.patient_id || getDefaultPatientIdForUser(req.user) || "P001");
  const message = String(req.body?.message || "SOS khẩn cấp từ ứng dụng COPD Care");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền gửi SOS cho bệnh nhân này" });

  await supabase.from("devices").upsert(
    {
      device_id: "MOBILE_APP",
      patient_id: patientId,
      device_name: "COPD Care Mobile App",
      online: true,
      last_seen_at: new Date().toISOString(),
    },
    { onConflict: "device_id" }
  );

  const { data, error } = await supabase
    .from("alerts_log")
    .insert({
      patient_id: patientId,
      device_id: "MOBILE_APP",
      alert_level: 3,
      alert_type: "SOS_APP",
      alert_value: 1,
      threshold_value: 1,
      message,
      timestamp: new Date().toISOString(),
    })
    .select("*")
    .single();

  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.user, "SOS", { alert_id: data.id, message }, patientId);
  res.json({ success: true, alert: data });
});

app.get("/api/my/activity", requireAuth, async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 50), 100);
  let query = supabase.from("app_activity_logs").select("*").order("created_at", { ascending: false }).limit(limit);

  if (req.user.role === "patient" || req.user.role === "family") {
    query = query.eq("user_id", req.user.user_id);
  } else if (req.user.role === "hospital" || req.user.role === "doctor") {
    query = query.eq("hospital_id", req.user.hospital_id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

// ============================================================
// MQTT SENSOR INGESTION
// ============================================================
function getAlertType(payload) {
  const msg = String(payload.message || payload.alert_message || "").toUpperCase();
  if (msg.includes("SPO2")) return "SpO2";
  if (msg.includes("HR")) return "HR";
  if (msg.includes("RR")) return "RR";
  if (msg.includes("NHIET") || msg.includes("TEMP")) return "Temp";
  return "General";
}

async function patientExists(patientId) {
  const { data } = await supabase.from("patients").select("patient_id").eq("patient_id", patientId).maybeSingle();
  return !!data;
}

async function resolveSensorPatientId(payload) {
  const incoming = payload.patient_id ? String(payload.patient_id).trim() : "";
  if (incoming && await patientExists(incoming)) return incoming;

  const deviceId = payload.device || payload.device_id || "COPD_01";
  const { data: device } = await supabase.from("devices").select("patient_id").eq("device_id", deviceId).maybeSingle();
  if (device?.patient_id && await patientExists(String(device.patient_id))) return String(device.patient_id);

  // Nếu ESP32 vẫn gửi P001 sau khi reset, backend tự gán vào bệnh nhân đầu tiên để tránh mất lịch sử đo.
  // Khi có nhiều bệnh nhân, nên sửa firmware ESP32 gửi đúng patient_id được cấp trong app.
  const { data: firstPatient } = await supabase
    .from("patients")
    .select("patient_id")
    .order("created_at", { ascending: true })
    .limit(1)
    .maybeSingle();
  if (firstPatient?.patient_id) return String(firstPatient.patient_id);

  return incoming || "P0001";
}

async function saveSensorData(payload) {
  const deviceId = payload.device || payload.device_id || "COPD_01";
  const patientId = await resolveSensorPatientId(payload);
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
      patient_id: patientId,
      device_name: "ESP32-S3 COPD Monitor",
      online: true,
      last_seen_at: new Date().toISOString(),
    },
    { onConflict: "device_id" }
  );

  const row = {
    patient_id: patientId,
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
    raw_payload: payload,
  };

  const { error } = await supabase.from("sensor_data").insert(row);
  if (error) {
    console.error("LOI LUU sensor_data:", error.message);
    return;
  }

  console.log("DA LUU DATA:", { patientId, deviceId, ready, rr, hr, spo2, temperature, alertLevel });

  if (ready && alertLevel > 0) {
    const alertType = getAlertType(payload);
    const { error: alertError } = await supabase.from("alerts_log").insert({
      patient_id: patientId,
      device_id: deviceId,
      alert_level: alertLevel,
      alert_type: alertType,
      alert_value: 0,
      threshold_value: 0,
      message: alertMessage || "CANH BAO TU THIET BI",
      timestamp: new Date().toISOString(),
    });
    if (alertError) console.error("LOI LUU alerts_log:", alertError.message);
  }
}

const mqttClientId = `copd_backend_${Math.random().toString(16).slice(2)}`;
const mqttClient = mqtt.connect(MQTT_URL, {
  clientId: mqttClientId,
  clean: true,
  reconnectPeriod: 5000,
  connectTimeout: 10000,
});

mqttClient.on("connect", () => {
  console.log("MQTT CONNECTED:", MQTT_URL);
  mqttClient.subscribe(MQTT_TOPIC, { qos: 0 }, (err) => {
    if (err) console.error("LOI SUBSCRIBE MQTT:", err.message);
    else console.log("DA SUBSCRIBE TOPIC:", MQTT_TOPIC);
  });
});

mqttClient.on("message", async (topic, message) => {
  try {
    const payload = JSON.parse(message.toString());
    console.log("NHAN MQTT:", topic, payload);
    await saveSensorData(payload);
  } catch (err) {
    console.error("LOI XU LY MQTT:", err.message);
  }
});

mqttClient.on("error", (err) => console.error("MQTT ERROR:", err.message));

// ============================================================
// PUBLIC DASHBOARD LEGACY API
// ============================================================
app.get("/", (req, res) => res.json({ status: "OK", name: "COPD Monitor Backend V8", mqtt_topic: MQTT_TOPIC }));
app.get("/health", (req, res) => res.json({ status: "OK", version: "V11_SENSOR_LIVE_FALLBACK", mqtt_connected: mqttClient.connected, time: new Date().toISOString() }));

app.get("/api/latest", async (req, res) => {
  const patientId = req.query.patient_id || "P001";
  const { data, error } = await supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(1).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get("/api/history", async (req, res) => {
  const patientId = req.query.patient_id || "P001";
  const limit = Math.min(toNumber(req.query.limit, 100), 500);
  const dateRange = buildDateRange(req.query.date);

  let query = supabase
    .from("sensor_data")
    .select("*")
    .eq("patient_id", patientId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (dateRange) query = query.gte("timestamp", dateRange.start).lt("timestamp", dateRange.end);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

app.get("/api/alerts", async (req, res) => {
  const patientId = req.query.patient_id || "P001";
  const limit = Math.min(toNumber(req.query.limit, 50), 200);
  const { data, error } = await supabase.from("alerts_log").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(limit);
  if (error) return res.status(500).json({ error: error.message });
  res.json(Array.isArray(data) ? data : []);
});

app.listen(PORT, () => console.log(`COPD BACKEND V8 RUNNING ON PORT ${PORT}`));
