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
const APP_JWT_SECRET = process.env.APP_JWT_SECRET || "COPD_DEMO_SECRET_CHANGE_THIS_IN_RENDER";

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("THIEU SUPABASE_URL HOAC SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ============================================================
// DEMO FALLBACK ACCOUNTS
// Các tài khoản tạo thật sẽ lưu trong app_users Supabase.
// ============================================================
const demoUsers = [
  {
    user_id: "U_PATIENT_001",
    email: "patient@example.com",
    password: "123456",
    full_name: "Bệnh nhân P001",
    phone: "",
    role: "patient",
    patient_id: "P001",
    hospital_id: "H001",
    allowed_patients: ["P001"],
  },
  {
    user_id: "U_FAMILY_001",
    email: "family@example.com",
    password: "123456",
    full_name: "Người nhà bệnh nhân P001",
    phone: "",
    role: "family",
    patient_id: "P001",
    hospital_id: "H001",
    allowed_patients: ["P001"],
  },
  {
    user_id: "U_DOCTOR_001",
    email: "doctor@example.com",
    password: "123456",
    full_name: "BS. Hô hấp COPD",
    phone: "",
    role: "doctor",
    patient_id: null,
    hospital_id: "H001",
    allowed_patients: ["P001", "P002", "P003"],
  },
  {
    user_id: "U_HOSPITAL_001",
    email: "hospital@example.com",
    password: "123456",
    full_name: "Bệnh viện Hô hấp COPD Demo",
    phone: "",
    role: "hospital",
    patient_id: null,
    hospital_id: "H001",
    allowed_patients: ["P001", "P002", "P003"],
  },
  {
    user_id: "U_ADMIN_001",
    email: "admin@example.com",
    password: "123456",
    full_name: "Quản trị viên hệ thống",
    phone: "",
    role: "admin",
    patient_id: null,
    hospital_id: null,
    allowed_patients: ["P001", "P002", "P003"],
  },
];

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

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "").trim();
  const user = verifyToken(token);

  if (!user) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Bạn chưa đăng nhập hoặc token không hợp lệ",
    });
  }

  req.user = user;
  next();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function makeId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

function makePatientId() {
  return `P${Date.now().toString().slice(-7)}`;
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

  return user.patient_id ? [String(user.patient_id)] : ["P001"];
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
    return res.json([
      {
        hospital_id: "H001",
        hospital_name: "Bệnh viện Hô hấp COPD Demo",
        address: "Tư vấn online",
        phone: "0900000001",
        email: "hospital@example.com",
        active: true,
      },
    ]);
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

  let hospitalId = body.hospital_id ? String(body.hospital_id).trim() : null;
  let patientId = body.patient_id ? String(body.patient_id).trim() : null;
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
    patientId = patientId || makePatientId();
    allowedPatients = [patientId];

    await supabase.from("patients").upsert(
      {
        patient_id: patientId,
        full_name: fullName,
        phone,
        hospital_id: hospitalId,
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
    patientId = patientId || "P001";
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

  const demo = demoUsers.find(
    (u) => u.email.toLowerCase() === email && u.password === password
  );

  if (!demo) {
    return res.status(401).json({ error: "LOGIN_FAILED", message: "Email hoặc mật khẩu không đúng" });
  }

  const safeUser = {
    user_id: demo.user_id,
    email: demo.email,
    full_name: demo.full_name,
    phone: demo.phone || "",
    role: demo.role,
    patient_id: demo.patient_id,
    hospital_id: demo.hospital_id,
    allowed_patients: await getAllowedPatientsForUser(demo),
  };

  await logActivity(safeUser, "LOGIN_DEMO", { source: "demoUsers" }, safeUser.patient_id);
  res.json({ token: tokenForUser(safeUser), user: safeUser });
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
        hospital: "Bệnh viện Hô hấp COPD Demo",
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
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user));
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem dữ liệu bệnh nhân này" });

  const { data, error } = await supabase
    .from("sensor_data")
    .select("*")
    .eq("patient_id", patientId)
    .order("timestamp", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get("/api/my/history", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user));
  const limit = Math.min(Number(req.query.limit || 80), 200);
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem dữ liệu bệnh nhân này" });

  const { data, error } = await supabase
    .from("sensor_data")
    .select("*")
    .eq("patient_id", patientId)
    .order("timestamp", { ascending: false })
    .limit(limit);

  if (error) return res.status(500).json({ error: error.message });
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

async function saveSensorData(payload) {
  const deviceId = payload.device || payload.device_id || "COPD_01";
  const patientId = String(payload.patient_id || "P001");
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
app.get("/", (req, res) => res.json({ status: "OK", name: "COPD Monitor Backend V6", mqtt_topic: MQTT_TOPIC }));
app.get("/health", (req, res) => res.json({ status: "OK", version: "V6", mqtt_connected: mqttClient.connected, time: new Date().toISOString() }));

app.get("/api/latest", async (req, res) => {
  const patientId = req.query.patient_id || "P001";
  const { data, error } = await supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(1).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get("/api/history", async (req, res) => {
  const patientId = req.query.patient_id || "P001";
  const limit = Math.min(toNumber(req.query.limit, 100), 500);
  const { data, error } = await supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(limit);
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

app.listen(PORT, () => console.log(`COPD BACKEND V6 RUNNING ON PORT ${PORT}`));
