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

/* ============================================================
   COPD CARE BACKEND V22
   - ID bệnh nhân tăng dần: 01, 02, 03...
   - Không fallback lấy dữ liệu bệnh nhân khác
   - Dữ liệu cảm biến lưu theo thiết bị được gán: devices.device_id -> patient_id
   - Bác sĩ / Bệnh viện / Admin được gán nhanh thiết bị trên giao diện
   - Lịch sử đo chỉ lấy từ lúc tài khoản bệnh nhân được tạo
============================================================ */

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64url(input) {
  let s = String(input || "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
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
    const payload = JSON.parse(fromBase64url(body));
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
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Bạn chưa đăng nhập hoặc token không hợp lệ" });
  }
  try {
    let query = supabase.from("app_users").select("*").eq("active", true);
    if (tokenUser.user_id) query = query.eq("user_id", tokenUser.user_id);
    else query = query.eq("email", normalizeEmail(tokenUser.email));
    const { data: dbUser, error } = await query.maybeSingle();
    if (!error && dbUser) {
      req.user = await buildSafeUser(dbUser);
      return next();
    }
  } catch (err) {
    console.error("LOI REFRESH USER:", err.message);
  }
  req.user = tokenUser;
  return next();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function makeId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`;
}

function toNumber(value, defaultValue = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : defaultValue;
}

function toBooleanReady(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function hasOwn(obj, key) {
  return obj && Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== null && obj[key] !== undefined;
}

function boolFlag(obj, keys, defaultValue = false) {
  for (const key of keys) {
    if (hasOwn(obj, key)) return toBooleanReady(obj[key]);
  }
  return defaultValue;
}

function inRange(value, min, max) {
  const n = Number(value);
  return Number.isFinite(n) && n >= min && n <= max;
}

function normalizeLatestSensorRow(row) {
  const latest = { ...(row || {}) };
  if (latest.raw_payload && typeof latest.raw_payload === "object") {
    Object.assign(latest, latest.raw_payload);
  }

  const rrRaw = toNumber(latest.rr, 0);
  const spo2Raw = toNumber(latest.spo2, 0);
  const hrRaw = toNumber(latest.hr, 0);
  const tempRaw = toNumber(latest.temperature ?? latest.temp, 0);

  const maxReady = boolFlag(latest, ["max_ready", "finger_detected", "spo2_hr_ready", "max30102_ready"],
    toBooleanReady(latest.ready) && inRange(spo2Raw, 50, 100) && inRange(hrRaw, 30, 240));

  const rrOk = boolFlag(latest, ["ui_show_rr", "rr_valid"], inRange(rrRaw, 3, 60)) && inRange(rrRaw, 3, 60);
  const spo2Ok = maxReady && boolFlag(latest, ["ui_show_spo2", "spo2_valid"], inRange(spo2Raw, 50, 100)) && inRange(spo2Raw, 50, 100);
  const hrOk = maxReady && boolFlag(latest, ["ui_show_hr", "hr_valid"], inRange(hrRaw, 30, 240)) && inRange(hrRaw, 30, 240);
  const tempOk = boolFlag(latest, ["ui_show_temp", "temp_valid", "body_temp_ready"], inRange(tempRaw, 30, 45) && (rrOk || maxReady)) && inRange(tempRaw, 30, 45);
  const fullOk = rrOk && spo2Ok && hrOk && tempOk;

  latest.max_ready = maxReady ? 1 : 0;
  latest.ui_show_rr = rrOk ? 1 : 0;
  latest.ui_show_spo2 = spo2Ok ? 1 : 0;
  latest.ui_show_hr = hrOk ? 1 : 0;
  latest.ui_show_temp = tempOk ? 1 : 0;
  latest.rr_valid = rrOk ? 1 : 0;
  latest.spo2_valid = spo2Ok ? 1 : 0;
  latest.hr_valid = hrOk ? 1 : 0;
  latest.temp_valid = tempOk ? 1 : 0;
  latest.full_vitals_ready = fullOk ? 1 : 0;
  latest.device_worn = (rrOk || maxReady || tempOk || boolFlag(latest, ["device_worn", "worn"], false)) ? 1 : 0;

  // Không trả số đo cũ/sai ra app. Nếu cờ hiển thị = 0 thì gửi 0 để Flutter hiển thị ---.
  latest.rr = rrOk ? rrRaw : 0;
  latest.hr = hrOk ? hrRaw : 0;
  latest.spo2 = spo2Ok ? spo2Raw : 0;
  latest.temperature = tempOk ? tempRaw : 0;
  latest.temp = latest.temperature;
  latest.temp_raw = tempRaw;
  latest.ready = fullOk;
  latest.alert_message = latest.alert_message || latest.current_message || latest.message || "DANG CAP NHAT DU LIEU CAM BIEN";
  return latest;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.createHash("sha256").update(`${salt}:${password}`).digest("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(storedHash, password) {
  if (!storedHash || !storedHash.includes(":")) return false;
  const [salt, hash] = storedHash.split(":");
  const test = crypto.createHash("sha256").update(`${salt}:${password}`).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(test));
  } catch (_) {
    return false;
  }
}

async function isPasswordAlreadyUsed(password) {
  const { data, error } = await supabase.from("app_users").select("password_hash").eq("active", true);
  if (error || !Array.isArray(data)) return false;
  for (const row of data) {
    if (verifyPassword(row.password_hash, password)) return true;
  }
  return false;
}

function buildDateRange(dateValue) {
  if (!dateValue) return null;
  const s = String(dateValue).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const start = new Date(`${s}T00:00:00.000Z`);
  const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

async function nextPatientId() {
  const { data, error } = await supabase.rpc("next_patient_id");
  if (!error && data) return String(data);
  const ids = [];
  const { data: users } = await supabase.from("app_users").select("patient_id").eq("role", "patient").not("patient_id", "is", null).limit(1000);
  const { data: patients } = await supabase.from("patients").select("patient_id").not("patient_id", "is", null).limit(1000);
  for (const row of Array.isArray(users) ? users : []) ids.push(String(row.patient_id));
  for (const row of Array.isArray(patients) ? patients : []) ids.push(String(row.patient_id));
  let max = 0;
  for (const id of ids) {
    if (/^\d+$/.test(id)) max = Math.max(max, Number(id));
  }
  const next = max + 1;
  return next < 100 ? String(next).padStart(2, "0") : String(next);
}

async function getPatientCreatedAt(patientId) {
  const pid = String(patientId || "").trim();
  if (!pid) return null;
  const { data: userRows } = await supabase
    .from("app_users")
    .select("created_at")
    .eq("role", "patient")
    .eq("patient_id", pid)
    .eq("active", true)
    .order("created_at", { ascending: true })
    .limit(1);
  if (Array.isArray(userRows) && userRows.length > 0 && userRows[0].created_at) return userRows[0].created_at;
  const { data: patient } = await supabase.from("patients").select("created_at").eq("patient_id", pid).maybeSingle();
  return patient?.created_at || null;
}

async function querySensorRowsForAccount(patientId, limit = 300, dateRange = null) {
  const pid = String(patientId || "").trim();
  const createdAt = await getPatientCreatedAt(pid);
  let query = supabase.from("sensor_data").select("*").eq("patient_id", pid).order("timestamp", { ascending: false }).limit(limit);
  if (createdAt) query = query.gte("timestamp", createdAt);
  if (dateRange) query = query.gte("timestamp", dateRange.start).lt("timestamp", dateRange.end);
  return query;
}

async function getLatestVitalsRow(patientId) {
  const { data, error } = await querySensorRowsForAccount(patientId, 1, null);
  if (error) throw error;
  if (!Array.isArray(data) || data.length === 0) return null;

  // Chỉ trả về bản ghi mới nhất đúng như ESP32 vừa gửi.
  // KHÔNG lấy lại số đo dương cũ từ các bản ghi trước, vì khi bỏ tay khỏi MAX30102
  // hoặc RR bị mất, app phải hiển thị --- để tránh lưu/hiển thị sai dữ liệu.
  const latest = normalizeLatestSensorRow(data[0]);
  return latest;
}

function getDefaultPatientIdForUser(user) {
  if (user?.role === "patient") return user.patient_id;
  if (Array.isArray(user?.allowed_patients) && user.allowed_patients.length > 0) return user.allowed_patients[0];
  return null;
}

function canAccessPatient(user, patientId) {
  if (!user || !patientId) return false;
  if (user.role === "admin") return true;
  return Array.isArray(user.allowed_patients) && user.allowed_patients.includes(String(patientId));
}

async function getAllowedPatientsForUser(user) {
  if (!user) return [];
  if (user.role === "admin") {
    const { data } = await supabase.from("patients").select("patient_id").order("patient_id", { ascending: true }).limit(1000);
    return Array.isArray(data) ? data.map((r) => String(r.patient_id)) : [];
  }
  if (user.role === "hospital" || user.role === "doctor") {
    if (!user.hospital_id) return [];
    const { data } = await supabase
      .from("hospital_patient_links")
      .select("patient_id")
      .eq("hospital_id", user.hospital_id)
      .eq("status", "active")
      .limit(1000);
    return Array.isArray(data) ? data.map((r) => String(r.patient_id)) : [];
  }
  if (Array.isArray(user.allowed_patients) && user.allowed_patients.length > 0) return user.allowed_patients.map(String);
  return user.patient_id ? [String(user.patient_id)] : [];
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
    allowed_patients: Array.isArray(dbUser.allowed_patients) ? dbUser.allowed_patients.map(String) : [],
  };
  base.allowed_patients = await getAllowedPatientsForUser(base);
  return base;
}

function tokenForUser(safeUser) {
  return signToken({ ...safeUser, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 });
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

function getAlertType(payload) {
  const msg = String(payload.message || payload.alert_message || "").toUpperCase();
  if (msg.includes("SPO2")) return "SpO2";
  if (msg.includes("HR")) return "HR";
  if (msg.includes("RR")) return "RR";
  if (msg.includes("NHIET") || msg.includes("TEMP")) return "Temp";
  return "General";
}

app.get("/api/hospitals", async (req, res) => {
  const { data, error } = await supabase.from("hospitals").select("hospital_id,hospital_name,address,phone,email,active").eq("active", true).order("hospital_name", { ascending: true });
  if (error) return res.status(500).json({ error: error.message, message: "Không tải được danh sách bệnh viện đã đăng ký" });
  return res.json(Array.isArray(data) ? data : []);
});

app.post("/api/auth/register", async (req, res) => {
  const body = req.body || {};
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const fullName = String(body.full_name || "").trim();
  const phone = String(body.phone || "").trim();
  const role = String(body.role || "patient").trim();
  const allowedRoles = ["patient", "family", "doctor", "hospital", "admin"];

  if (!email || !password || password.length < 6 || !fullName) return res.status(400).json({ error: "MISSING_FIELDS", message: "Cần nhập họ tên, email và mật khẩu tối thiểu 6 ký tự" });
  if (!allowedRoles.includes(role)) return res.status(400).json({ error: "INVALID_ROLE", message: "Vai trò không hợp lệ" });

  const { data: existed } = await supabase.from("app_users").select("email").eq("email", email).maybeSingle();
  if (existed) return res.status(409).json({ error: "EMAIL_EXISTS", message: "Email này đã được đăng ký" });

  if (await isPasswordAlreadyUsed(password)) {
    return res.status(409).json({ error: "PASSWORD_ALREADY_USED", message: "Mật khẩu này đã được tài khoản khác sử dụng. Vui lòng tạo mật khẩu khác." });
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
      updated_at: new Date().toISOString(),
    });
    if (hospitalError) return res.status(500).json({ error: hospitalError.message, message: "Không tạo được tài khoản bệnh viện" });
  }

  if (["patient", "family", "doctor"].includes(role) && !hospitalId) return res.status(400).json({ error: "MISSING_HOSPITAL", message: "Cần chọn bệnh viện đã đăng ký trên hệ thống" });

  if (role === "patient") {
    patientId = await nextPatientId();
    allowedPatients = [patientId];
    const now = new Date().toISOString();
    const { error: patientError } = await supabase.from("patients").upsert({
      patient_id: patientId,
      full_name: fullName,
      phone,
      hospital_id: hospitalId,
      date_of_birth: dateOfBirth,
      age,
      diagnosis: "COPD cần theo dõi hô hấp",
      created_at: now,
    }, { onConflict: "patient_id" });
    if (patientError) return res.status(500).json({ error: patientError.message, message: "Không tạo được hồ sơ bệnh nhân" });
    await supabase.from("hospital_patient_links").upsert({ hospital_id: hospitalId, patient_id: patientId, status: "active", created_at: now }, { onConflict: "hospital_id,patient_id" });
  }

  if (role === "family") {
    if (!patientId) return res.status(400).json({ error: "MISSING_PATIENT_ID", message: "Người nhà cần nhập mã bệnh nhân cần theo dõi" });
    const { data: linkedPatient } = await supabase.from("hospital_patient_links").select("patient_id").eq("hospital_id", hospitalId).eq("patient_id", patientId).eq("status", "active").maybeSingle();
    if (!linkedPatient) return res.status(404).json({ error: "PATIENT_NOT_FOUND_IN_HOSPITAL", message: "Không tìm thấy mã bệnh nhân này trong bệnh viện đã chọn" });
    allowedPatients = [patientId];
  }

  if (role === "doctor") {
    allowedPatients = [];
    const doctorId = `D${Date.now().toString().slice(-7)}`;
    const { data: hospital } = await supabase.from("hospitals").select("hospital_name").eq("hospital_id", hospitalId).maybeSingle();
    await supabase.from("doctors").insert({ doctor_id: doctorId, hospital_id: hospitalId, full_name: fullName, specialty: String(body.specialty || "Hô hấp - COPD"), hospital: hospital?.hospital_name || "Bệnh viện đã đăng ký", experience_years: toNumber(body.experience_years, 0), price: toNumber(body.price, 0), location: "Tư vấn online", rating: 5, created_at: new Date().toISOString() });
  }

  const now = new Date().toISOString();
  const userRow = { user_id: makeId("U"), email, password_hash: hashPassword(password), full_name: fullName, phone, role, date_of_birth: role === "patient" ? dateOfBirth : null, age: role === "patient" ? age : null, patient_id: patientId, hospital_id: hospitalId, allowed_patients: allowedPatients, active: true, created_at: now, updated_at: now };
  const { data, error } = await supabase.from("app_users").insert(userRow).select("*").single();
  if (error) return res.status(500).json({ error: error.message, message: "Không tạo được tài khoản người dùng" });
  const safeUser = await buildSafeUser(data);
  await logActivity(safeUser, "REGISTER", { role, hospital_id: hospitalId }, patientId);
  return res.json({ token: tokenForUser(safeUser), user: safeUser, message: "Đăng ký thành công" });
});

app.post("/api/auth/login", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");
  const { data: dbUser, error } = await supabase.from("app_users").select("*").eq("email", email).eq("active", true).maybeSingle();
  if (!error && dbUser) {
    if (!verifyPassword(dbUser.password_hash, password)) return res.status(401).json({ error: "LOGIN_FAILED", message: "Email hoặc mật khẩu không đúng" });
    const safeUser = await buildSafeUser(dbUser);
    await logActivity(safeUser, "LOGIN", { source: "app_users" }, safeUser.patient_id);
    return res.json({ token: tokenForUser(safeUser), user: safeUser });
  }
  return res.status(401).json({ error: "LOGIN_FAILED", message: "Email hoặc mật khẩu không đúng hoặc tài khoản chưa được đăng ký" });
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: req.user }));

app.get("/api/my/patients", requireAuth, async (req, res) => {
  const allowed = await getAllowedPatientsForUser(req.user);
  if (allowed.length === 0) return res.json([]);
  const { data, error } = await supabase.from("patients").select("*").in("patient_id", allowed).order("patient_id", { ascending: true });
  if (error) return res.status(500).json({ error: error.message, message: "Không tải được danh sách bệnh nhân" });
  return res.json(Array.isArray(data) ? data : []);
});

app.get("/api/patient/full", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem bệnh nhân này" });
  const [profile, latest, history, alerts, appointments] = await Promise.all([
    supabase.from("patients").select("*").eq("patient_id", patientId).maybeSingle(),
    supabase.from("sensor_data").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(1).maybeSingle(),
    querySensorRowsForAccount(patientId, 80, null),
    supabase.from("alerts_log").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(30),
    supabase.from("doctor_appointments").select("*").eq("patient_id", patientId).order("appointment_date", { ascending: true }).order("appointment_time", { ascending: true }).limit(50),
  ]);
  return res.json({ profile: profile.data || null, latest: latest.data || null, history: Array.isArray(history.data) ? history.data : [], alerts: Array.isArray(alerts.data) ? alerts.data : [], appointments: Array.isArray(appointments.data) ? appointments.data : [] });
});

app.get("/api/devices", requireAuth, async (req, res) => {
  if (!["doctor", "hospital", "admin"].includes(req.user.role)) return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ, bệnh viện hoặc admin được xem thiết bị" });
  const { data, error } = await supabase.from("devices").select("*").order("device_id", { ascending: true });
  if (error) return res.status(500).json({ error: error.message, message: "Không tải được danh sách thiết bị" });
  return res.json(Array.isArray(data) ? data : []);
});

app.post("/api/devices/assign", requireAuth, async (req, res) => {
  try {
    if (!["doctor", "hospital", "admin"].includes(req.user.role)) return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ, bệnh viện hoặc admin được gắn thiết bị" });
    const deviceId = String(req.body?.device_id || "COPD_01").trim();
    const patientId = String(req.body?.patient_id || "").trim();
    if (!deviceId || !patientId) return res.status(400).json({ error: "MISSING_FIELDS", message: "Thiếu device_id hoặc patient_id" });
    if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền gắn thiết bị cho bệnh nhân này" });
    const { data: patient, error: patientError } = await supabase.from("patients").select("patient_id, full_name, hospital_id").eq("patient_id", patientId).maybeSingle();
    if (patientError || !patient) return res.status(404).json({ error: "PATIENT_NOT_FOUND", message: "Không tìm thấy bệnh nhân cần gắn thiết bị" });
    const now = new Date().toISOString();
    const { data: device, error } = await supabase.from("devices").upsert({ device_id: deviceId, patient_id: patientId, device_name: deviceId === "COPD_01" ? "ESP32-S3 COPD Monitor" : "COPD Care Device", active: true, online: true, last_seen_at: now, updated_at: now, created_at: now }, { onConflict: "device_id" }).select("*").single();
    if (error) return res.status(500).json({ error: error.message, message: "Không gắn được thiết bị" });
    await logActivity(req.user, "ASSIGN_DEVICE", { device_id: deviceId, patient_name: patient.full_name }, patientId);
    return res.json({ success: true, message: `Đã gắn thiết bị ${deviceId} cho bệnh nhân ${patientId}`, device });
  } catch (err) {
    return res.status(500).json({ error: err.message, message: "Lỗi server khi gắn thiết bị" });
  }
});

function canManageAppointments(user) {
  return user && ["admin", "doctor", "hospital"].includes(user.role);
}

app.get("/api/doctors", requireAuth, async (req, res) => {
  let query = supabase.from("doctors").select("*").order("full_name", { ascending: true });
  if (["patient", "family", "doctor", "hospital"].includes(req.user.role) && req.user.hospital_id) query = query.eq("hospital_id", req.user.hospital_id);
  const { data, error } = await query;
  if (error || !Array.isArray(data) || data.length === 0) return res.json([{ doctor_id: "D001", hospital_id: req.user.hospital_id || null, full_name: "BS. Hô hấp COPD", specialty: "Hô hấp - COPD", hospital: "Bệnh viện đã đăng ký", experience_years: 8, price: 150000, location: "Tư vấn online", rating: 4.8 }]);
  return res.json(data);
});

app.post("/api/my/appointments", requireAuth, async (req, res) => {
  const body = req.body || {};
  const doctorId = String(body.doctor_id || "D001");
  const appointmentDate = String(body.appointment_date || "").trim();
  const appointmentTime = String(body.appointment_time || "").trim();
  const reason = String(body.reason || "Tái khám COPD định kỳ").trim();
  const patientId = String(body.patient_id || getDefaultPatientIdForUser(req.user) || "");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền đặt lịch cho bệnh nhân này" });
  if (!appointmentDate || !appointmentTime) return res.status(400).json({ error: "MISSING_FIELDS", message: "Thiếu ngày hoặc khung giờ khám" });
  const { data: doctor } = await supabase.from("doctors").select("doctor_id,hospital_id,full_name").eq("doctor_id", doctorId).maybeSingle();
  const hospitalId = doctor?.hospital_id || req.user.hospital_id || null;
  const { data: lastRows, error: queueError } = await supabase.from("doctor_appointments").select("queue_number").eq("doctor_id", doctorId).eq("appointment_date", appointmentDate).eq("appointment_time", appointmentTime).order("queue_number", { ascending: false }).limit(1);
  if (queueError) return res.status(500).json({ error: queueError.message });
  const lastQueue = Array.isArray(lastRows) && lastRows.length > 0 ? Number(lastRows[0].queue_number || 0) : 0;
  const row = { doctor_id: doctorId, hospital_id: hospitalId, patient_id: patientId, patient_name: body.patient_name || req.user.full_name || patientId, requester_user_id: req.user.user_id, requester_name: req.user.full_name, requester_role: req.user.role, appointment_date: appointmentDate, appointment_time: appointmentTime, queue_number: lastQueue + 1, reason, status: "pending", created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
  const { data, error } = await supabase.from("doctor_appointments").insert(row).select("*").single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.user, "CREATE_APPOINTMENT", { appointment_id: data.appointment_id, doctor_id: doctorId, appointment_date: appointmentDate, appointment_time: appointmentTime }, patientId);
  return res.json({ success: true, appointment: data, message: `Đã đặt lịch. Số thứ tự trong khung ${appointmentTime} là ${data.queue_number}` });
});

app.get("/api/my/appointments", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem lịch của bệnh nhân này" });
  const { data, error } = await supabase.from("doctor_appointments").select("*").eq("patient_id", patientId).order("appointment_date", { ascending: true }).order("appointment_time", { ascending: true }).order("queue_number", { ascending: true }).limit(100);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

app.get("/api/doctor/appointments", requireAuth, async (req, res) => {
  if (!canManageAppointments(req.user)) return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ/bệnh viện/admin được xem danh sách lịch hẹn" });
  const status = String(req.query.status || "").trim();
  let query = supabase.from("doctor_appointments").select("*").order("appointment_date", { ascending: true }).order("appointment_time", { ascending: true }).order("queue_number", { ascending: true });
  if (req.user.role !== "admin" && req.user.hospital_id) query = query.eq("hospital_id", req.user.hospital_id);
  if (status) query = query.eq("status", status);
  const { data, error } = await query.limit(300);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

app.patch("/api/doctor/appointments/:id/status", requireAuth, async (req, res) => {
  if (!canManageAppointments(req.user)) return res.status(403).json({ error: "FORBIDDEN", message: "Chỉ bác sĩ/bệnh viện/admin được cập nhật lịch hẹn" });
  const status = String(req.body?.status || "").trim();
  const allowed = ["pending", "confirmed", "done", "cancelled"];
  if (!allowed.includes(status)) return res.status(400).json({ error: "INVALID_STATUS", message: "Trạng thái không hợp lệ" });
  const { data, error } = await supabase.from("doctor_appointments").update({ status, updated_at: new Date().toISOString() }).eq("appointment_id", req.params.id).select("*").single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.user, "UPDATE_APPOINTMENT_STATUS", { appointment_id: req.params.id, status }, data.patient_id);
  return res.json({ success: true, appointment: data });
});

app.get("/api/my/latest", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem dữ liệu bệnh nhân này" });
  try {
    const data = await getLatestVitalsRow(patientId);
    return res.json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/my/history", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "");
  const limit = Math.min(Number(req.query.limit || 80), 500);
  const dateRange = buildDateRange(req.query.date);
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem lịch sử đo bệnh nhân này" });
  const { data, error } = await querySensorRowsForAccount(patientId, limit, dateRange);
  if (error) return res.status(500).json({ error: error.message });
  if (String(req.query.track || "") === "1") await logActivity(req.user, "VIEW_MEASUREMENT_HISTORY", { patient_id: patientId, date: req.query.date || "latest", from_created_at: await getPatientCreatedAt(patientId), count: Array.isArray(data) ? data.length : 0 }, patientId);
  return res.json(Array.isArray(data) ? data : []);
});

app.get("/api/my/alerts", requireAuth, async (req, res) => {
  const patientId = String(req.query.patient_id || getDefaultPatientIdForUser(req.user) || "");
  const limit = Math.min(Number(req.query.limit || 50), 200);
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền xem cảnh báo bệnh nhân này" });
  const { data, error } = await supabase.from("alerts_log").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(limit);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

app.post("/api/my/sos", requireAuth, async (req, res) => {
  const patientId = String(req.body?.patient_id || getDefaultPatientIdForUser(req.user) || "");
  const message = String(req.body?.message || "SOS khẩn cấp từ ứng dụng COPD Care");
  if (!canAccessPatient(req.user, patientId)) return res.status(403).json({ error: "FORBIDDEN", message: "Bạn không có quyền gửi SOS cho bệnh nhân này" });
  const now = new Date().toISOString();
  await supabase.from("devices").upsert({ device_id: "MOBILE_APP", patient_id: patientId, device_name: "COPD Care Mobile App", active: true, online: true, last_seen_at: now, updated_at: now }, { onConflict: "device_id" });
  const { data, error } = await supabase.from("alerts_log").insert({ patient_id: patientId, device_id: "MOBILE_APP", alert_level: 3, alert_type: "SOS_APP", alert_value: 1, threshold_value: 1, message, timestamp: now }).select("*").single();
  if (error) return res.status(500).json({ error: error.message });
  await logActivity(req.user, "SOS", { alert_id: data.id, message }, patientId);
  return res.json({ success: true, alert: data });
});

app.get("/api/my/activity", requireAuth, async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 50), 100);
  let query = supabase.from("app_activity_logs").select("*").order("created_at", { ascending: false }).limit(limit);
  if (req.user.role === "patient" || req.user.role === "family") query = query.eq("user_id", req.user.user_id);
  else if (req.user.role === "hospital" || req.user.role === "doctor") query = query.eq("hospital_id", req.user.hospital_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

async function patientExists(patientId) {
  const { data } = await supabase.from("patients").select("patient_id").eq("patient_id", patientId).maybeSingle();
  return !!data;
}

async function resolveSensorPatientId(payload) {
  const deviceId = String(payload.device || payload.device_id || "COPD_01");
  const { data: device, error } = await supabase.from("devices").select("patient_id, active").eq("device_id", deviceId).maybeSingle();
  if (!error && device?.active && device?.patient_id) {
    const pid = String(device.patient_id);
    if (await patientExists(pid)) return pid;
  }
  return null;
}

async function saveSensorData(payload) {
  const deviceId = String(payload.device || payload.device_id || "COPD_01");
  const patientId = await resolveSensorPatientId(payload);
  const now = new Date().toISOString();
  if (!patientId) {
    console.log("THIET BI CHUA DUOC GAN CHO BENH NHAN:", deviceId);
    await supabase.from("devices").upsert({ device_id: deviceId, device_name: "ESP32-S3 COPD Monitor", active: false, online: true, last_seen_at: now, updated_at: now }, { onConflict: "device_id" });
    return;
  }

  // Chuẩn hóa dữ liệu ngay lúc lưu: nếu ESP báo cảm biến không hợp lệ thì lưu 0.
  // raw_payload vẫn giữ toàn bộ gói MQTT gốc để debug và hiển thị trạng thái dự báo.
  const normalized = normalizeLatestSensorRow({ ...payload, raw_payload: payload });
  const ready = !!normalized.ready;
  const rr = toNumber(normalized.rr, 0);
  const hr = toNumber(normalized.hr, 0);
  const spo2 = toNumber(normalized.spo2, 0);
  const temperature = toNumber(normalized.temp ?? normalized.temperature, 0);
  const flexRaw = toNumber(payload.flex_raw, 0);
  const flexFiltered = toNumber(payload.flex_filtered, 0);
  const flexBaseline = toNumber(payload.flex_baseline, 0);
  const flexDelta = toNumber(payload.flex_delta ?? payload.amp, 0);
  const alertLevel = toNumber(payload.alert ?? payload.alert_level, 0);
  const alertMessage = payload.message || payload.alert_message || "";

  await supabase.from("devices").upsert({ device_id: deviceId, patient_id: patientId, device_name: "ESP32-S3 COPD Monitor", active: true, online: true, last_seen_at: now, updated_at: now }, { onConflict: "device_id" });

  const row = { patient_id: patientId, device_id: deviceId, ready, rr, hr, spo2, temperature, flex_raw: flexRaw, flex_filtered: flexFiltered, flex_baseline: flexBaseline, flex_delta: flexDelta, alert_level: alertLevel, alert_message: alertMessage, raw_payload: payload };
  const { error } = await supabase.from("sensor_data").insert(row);
  if (error) {
    console.error("LOI LUU sensor_data:", error.message);
    return;
  }
  console.log("DA LUU DATA:", { patientId, deviceId, ready, rr, hr, spo2, temperature, alertLevel });

  if (ready && alertLevel > 0) {
    const alertType = getAlertType(payload);
    const { error: alertError } = await supabase.from("alerts_log").insert({ patient_id: patientId, device_id: deviceId, alert_level: alertLevel, alert_type: alertType, alert_value: spo2 || hr || rr || temperature || 0, threshold_value: 0, message: alertMessage || "CANH BAO TU THIET BI", timestamp: now });
    if (alertError) console.error("LOI LUU alerts_log:", alertError.message);
  }
}

const mqttClientId = `copd_backend_${Math.random().toString(16).slice(2)}`;
const mqttClient = mqtt.connect(MQTT_URL, { clientId: mqttClientId, clean: true, reconnectPeriod: 5000, connectTimeout: 10000 });

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

app.get("/", (req, res) => res.json({ status: "OK", name: "COPD Monitor Backend V22", mqtt_topic: MQTT_TOPIC }));
app.get("/health", (req, res) => res.json({ status: "OK", version: "V22_PREDICT_FIELDS_RAW_PAYLOAD_NO_OLD_VITALS", mqtt_connected: mqttClient.connected, mqtt_topic: MQTT_TOPIC, time: new Date().toISOString() }));

app.get("/api/latest", async (req, res) => {
  const patientId = String(req.query.patient_id || "");
  if (!patientId) return res.json(null);
  const { data, error } = await getLatestVitalsRow(patientId).then((row) => ({ data: row, error: null })).catch((err) => ({ data: null, error: err }));
  if (error) return res.status(500).json({ error: error.message });
  return res.json(data);
});

app.get("/api/history", async (req, res) => {
  const patientId = String(req.query.patient_id || "");
  const limit = Math.min(toNumber(req.query.limit, 100), 500);
  const dateRange = buildDateRange(req.query.date);
  if (!patientId) return res.json([]);
  const { data, error } = await querySensorRowsForAccount(patientId, limit, dateRange);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

app.get("/api/alerts", async (req, res) => {
  const patientId = String(req.query.patient_id || "");
  const limit = Math.min(toNumber(req.query.limit, 50), 200);
  if (!patientId) return res.json([]);
  const { data, error } = await supabase.from("alerts_log").select("*").eq("patient_id", patientId).order("timestamp", { ascending: false }).limit(limit);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(Array.isArray(data) ? data : []);
});

app.listen(PORT, () => console.log(`COPD BACKEND V22 RUNNING ON PORT ${PORT}`));
