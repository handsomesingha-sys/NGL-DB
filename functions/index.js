"use strict";

/**
 * ================================================================
 * ActiGallery — Firebase Cloud Functions Backend
 * ================================================================
 *
 * Runtime:
 *   Node.js 20
 *   Firebase Cloud Functions v2
 *
 * Services:
 *   Firebase Authentication
 *   Cloud Firestore
 *   ImgBB Image Hosting API
 *
 * Region:
 *   asia-southeast1
 *
 * Required Firebase Secrets:
 *   IMGBB_API_KEY
 *   BOOTSTRAP_KEY
 *
 * Firestore collections:
 *   users
 *   organizations
 *   categories
 *   albums
 *   photos
 *
 * Callable functions:
 *   dashboardApi
 *   uploadImage
 *   bootstrapAdmin
 *
 * IMPORTANT:
 *   - Never place secrets in frontend HTML.
 *   - Never trust a role sent by the client.
 *   - Every privileged operation checks Firestore user profile.
 *   - Album managers are restricted to their organization.
 *   - Bootstrap requires a secret and is disabled after an admin
 *     account has already been created.
 * ================================================================
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");

const admin = require("firebase-admin");
const crypto = require("node:crypto");

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const auth = admin.auth();
const FieldValue = admin.firestore.FieldValue;
const Timestamp = admin.firestore.Timestamp;

const REGION = "asia-southeast1";
const APP_NAME = "ActiGallery";
const APP_VERSION = "1.0.0";

const IMGBB_API_KEY = defineSecret("IMGBB_API_KEY");
const BOOTSTRAP_KEY = defineSecret("BOOTSTRAP_KEY");

const IMG_BB_UPLOAD_ENDPOINT = "https://api.imgbb.com/1/upload";
const INTERNAL_AUTH_DOMAIN = "users.actigallery.app";

const MAX_IMAGE_BYTES = 7 * 1024 * 1024;
const MAX_BASE64_LENGTH = Math.ceil(MAX_IMAGE_BYTES * 4 / 3) + 16;
const MAX_TITLE_LENGTH = 160;
const MAX_DESCRIPTION_LENGTH = 5000;
const MAX_NAME_LENGTH = 180;
const MAX_CATEGORY_LENGTH = 100;
const MAX_USERNAME_LENGTH = 64;
const MAX_PASSWORD_LENGTH = 128;
const MAX_PHOTOS_PER_ALBUM = 2000;
const MAX_BATCH_OPERATIONS = 400;
const MAX_DASHBOARD_ALBUMS = 2000;
const MAX_DASHBOARD_USERS = 2000;
const MAX_DASHBOARD_ORGANIZATIONS = 1000;
const MAX_DASHBOARD_CATEGORIES = 1000;

const ROLE_ADMIN = "admin";
const ROLE_ALBUM_MANAGER = "album_manager";

const ALBUM_STATUS_DRAFT = "draft";
const ALBUM_STATUS_PUBLISHED = "published";

const COLLECTIONS = Object.freeze({
  USERS: "users",
  ORGANIZATIONS: "organizations",
  CATEGORIES: "categories",
  ALBUMS: "albums",
  PHOTOS: "photos"
});

/**
 * ================================================================
 * General utility functions
 * ================================================================
 */

function throwInvalid(message) {
  throw new HttpsError("invalid-argument", message);
}

function throwForbidden(message = "คุณไม่มีสิทธิ์ดำเนินการนี้") {
  throw new HttpsError("permission-denied", message);
}

function throwNotFound(message = "ไม่พบข้อมูลที่ต้องการ") {
  throw new HttpsError("not-found", message);
}

function throwConflict(message) {
  throw new HttpsError("already-exists", message);
}

function throwFailed(message = "ดำเนินการไม่สำเร็จ") {
  throw new HttpsError("internal", message);
}

function requireString(value, fieldName, maxLength = 500) {
  if (typeof value !== "string") {
    throwInvalid(`${fieldName} ต้องเป็นข้อความ`);
  }

  const normalized = value.trim();

  if (!normalized) {
    throwInvalid(`กรุณาระบุ${fieldName}`);
  }

  if (normalized.length > maxLength) {
    throwInvalid(`${fieldName} ต้องมีความยาวไม่เกิน ${maxLength} ตัวอักษร`);
  }

  return normalized;
}

function optionalString(value, maxLength = 500) {
  if (value === undefined || value === null) {
    return "";
  }

  if (typeof value !== "string") {
    throwInvalid("ข้อมูลข้อความไม่ถูกต้อง");
  }

  const normalized = value.trim();

  if (normalized.length > maxLength) {
    throwInvalid(`ข้อความต้องมีความยาวไม่เกิน ${maxLength} ตัวอักษร`);
  }

  return normalized;
}

function requireObject(value, fieldName = "ข้อมูล") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throwInvalid(`${fieldName}ไม่ถูกต้อง`);
  }

  return value;
}

function normalizeUsername(value) {
  const username = requireString(value, "ชื่อผู้ใช้", MAX_USERNAME_LENGTH)
    .toLowerCase();

  if (!/^[a-z0-9._-]{3,64}$/.test(username)) {
    throwInvalid(
      "ชื่อผู้ใช้ต้องมี 3–64 ตัวอักษร และใช้ภาษาอังกฤษ ตัวเลข จุด ขีดกลาง หรือขีดล่าง"
    );
  }

  return username;
}

function usernameToAuthEmail(username) {
  return `${normalizeUsername(username)}@${INTERNAL_AUTH_DOMAIN}`;
}

function validatePassword(value) {
  if (typeof value !== "string") {
    throwInvalid("รหัสผ่านไม่ถูกต้อง");
  }

  if (value.length < 8 || value.length > MAX_PASSWORD_LENGTH) {
    throwInvalid("รหัสผ่านต้องมีความยาว 8–128 ตัวอักษร");
  }

  return value;
}

function normalizeRole(role) {
  const normalized = String(role || "").trim().toLowerCase();

  if (![ROLE_ADMIN, ROLE_ALBUM_MANAGER].includes(normalized)) {
    throwInvalid("บทบาทผู้ใช้งานไม่ถูกต้อง");
  }

  return normalized;
}

function normalizeImageMimeType(value) {
  const mimeType = String(value || "").trim().toLowerCase();

  const allowedTypes = new Set([
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/avif",
    "image/bmp",
    "image/tiff"
  ]);

  if (!allowedTypes.has(mimeType)) {
    throwInvalid("รองรับเฉพาะไฟล์รูปภาพที่ระบบกำหนด");
  }

  return mimeType;
}

function normalizeEventDate(value) {
  if (value === undefined || value === null || value === "") {
    return "";
  }

  if (typeof value !== "string") {
    throwInvalid("วันที่จัดกิจกรรมไม่ถูกต้อง");
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throwInvalid("วันที่จัดกิจกรรมต้องอยู่ในรูปแบบ YYYY-MM-DD");
  }

  const parsed = new Date(`${value}T00:00:00.000Z`);

  if (Number.isNaN(parsed.getTime())) {
    throwInvalid("วันที่จัดกิจกรรมไม่ถูกต้อง");
  }

  if (parsed.toISOString().slice(0, 10) !== value) {
    throwInvalid("วันที่จัดกิจกรรมไม่ถูกต้อง");
  }

  return value;
}

function normalizeNonNegativeInteger(value, fieldName, maximum = 1000000000) {
  const number = Number(value);

  if (!Number.isSafeInteger(number) || number < 0 || number > maximum) {
    throwInvalid(`${fieldName}ไม่ถูกต้อง`);
  }

  return number;
}

function normalizeHttpUrl(value, fieldName = "URL") {
  const urlString = requireString(value, fieldName, 4096);

  let parsed;

  try {
    parsed = new URL(urlString);
  } catch {
    throwInvalid(`${fieldName}ไม่ถูกต้อง`);
  }

  if (!["https:", "http:"].includes(parsed.protocol)) {
    throwInvalid(`${fieldName}ต้องเป็น HTTP หรือ HTTPS`);
  }

  return parsed.href;
}

function cleanDocumentData(data) {
  const result = {};

  for (const [key, value] of Object.entries(data || {})) {
    if (value !== undefined) {
      result[key] = value;
    }
  }

  return result;
}

function publicUser(user, organizationMap = new Map()) {
  const organization = organizationMap.get(user.organizationId);

  return {
    id: user.id,
    uid: user.uid || user.id,
    fullName: user.fullName || user.name || "",
    name: user.name || user.fullName || "",
    username: user.username || "",
    role: user.role || ROLE_ALBUM_MANAGER,
    organizationId: user.organizationId || "",
    organizationName:
      user.organizationName ||
      organization?.name ||
      "",
    disabled: Boolean(user.disabled),
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null
  };
}

function publicOrganization(organization) {
  return {
    id: organization.id,
    name: organization.name || "",
    logoUrl: organization.logoUrl || "",
    createdAt: organization.createdAt || null,
    updatedAt: organization.updatedAt || null
  };
}

function publicCategory(category) {
  return {
    id: category.id,
    name: category.name || "",
    createdAt: category.createdAt || null,
    updatedAt: category.updatedAt || null
  };
}

function publicPhoto(photo) {
  return {
    id: photo.id,
    albumId: photo.albumId,
    organizationId: photo.organizationId || "",
    url: photo.url || "",
    imageUrl: photo.url || "",
    thumbnailUrl: photo.thumbnailUrl || photo.url || "",
    name: photo.name || "",
    fileName: photo.name || "",
    order: Number.isInteger(photo.order) ? photo.order : 0,
    duplicateOf: photo.duplicateOf || null,
    createdAt: photo.createdAt || null,
    updatedAt: photo.updatedAt || null
  };
}

function publicAlbum(album, photos = []) {
  const orderedPhotos = [...photos].sort((a, b) => {
    const aOrder = Number.isInteger(a.order) ? a.order : 0;
    const bOrder = Number.isInteger(b.order) ? b.order : 0;

    if (aOrder !== bOrder) {
      return aOrder - bOrder;
    }

    return String(a.id).localeCompare(String(b.id));
  });

  return {
    id: album.id,
    title: album.title || "",
    description: album.description || "",
    categoryId: album.categoryId || "",
    categoryName: album.categoryName || "",
    eventDate: album.eventDate || "",
    organizationId: album.organizationId || "",
    organizationName: album.organizationName || "",
    coverUrl: album.coverUrl || orderedPhotos[0]?.url || "",
    thumbnailUrl: album.thumbnailUrl || orderedPhotos[0]?.thumbnailUrl || "",
    photoCount: Number(album.photoCount ?? orderedPhotos.length),
    status: album.status || ALBUM_STATUS_DRAFT,
    visibility: album.visibility || "public",
    photos: orderedPhotos.map(publicPhoto),
    createdBy: album.createdBy || "",
    createdAt: album.createdAt || null,
    updatedAt: album.updatedAt || null,
    publishedAt: album.publishedAt || null
  };
}

function nowTimestamp() {
  return Timestamp.now();
}

function isTruthy(value) {
  return value === true || value === "true" || value === 1;
}

function makeGeneratedPassword() {
  const number = crypto.randomInt(0, 1000000);
  return `GF${String(number).padStart(6, "0")}`;
}

function constantTimeSecretCompare(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string") {
    return false;
  }

  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);

  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function normalizePhotoInput(photo, index) {
  requireObject(photo, "ข้อมูลรูปภาพ");

  const url = normalizeHttpUrl(photo.url || photo.imageUrl, "URL รูปภาพ");
  const thumbnailUrl = photo.thumbnailUrl
    ? normalizeHttpUrl(photo.thumbnailUrl, "URL ภาพตัวอย่าง")
    : url;

  const name = optionalString(
    photo.name || photo.fileName || `รูปภาพ ${index + 1}`,
    255
  );

  const order = photo.order === undefined
    ? index
    : normalizeNonNegativeInteger(photo.order, "ลำดับรูปภาพ", 10000000);

  const duplicateOf = photo.duplicateOf
    ? optionalString(photo.duplicateOf, 256)
    : null;

  const id = photo.id
    ? optionalString(photo.id, 256)
    : "";

  return {
    id,
    url,
    thumbnailUrl,
    name,
    order,
    duplicateOf
  };
}

function ensureLimit(value, max, fieldName) {
  if (value > max) {
    throw new HttpsError(
      "resource-exhausted",
      `${fieldName}มีจำนวนเกินขีดจำกัดที่ระบบกำหนด`
    );
  }
}

function timestampMillis(value) {
  if (!value) return 0;

  if (typeof value.toMillis === "function") {
    return value.toMillis();
  }

  if (value instanceof Date) {
    return value.getTime();
  }

  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}

/**
 * ================================================================
 * Authentication and role verification
 * ================================================================
 */

async function requireAuthenticatedUser(request) {
  if (!request.auth || !request.auth.uid) {
    throw new HttpsError(
      "unauthenticated",
      "กรุณาเข้าสู่ระบบก่อนดำเนินการ"
    );
  }

  return request.auth.uid;
}

async function getUserProfile(uid) {
  const snapshot = await db.collection(COLLECTIONS.USERS).doc(uid).get();

  if (!snapshot.exists) {
    throw new HttpsError(
      "permission-denied",
      "ไม่พบข้อมูลผู้ใช้งานหรือบัญชียังไม่ได้รับสิทธิ์"
    );
  }

  const data = snapshot.data() || {};

  if (data.disabled === true) {
    throw new HttpsError(
      "permission-denied",
      "บัญชีนี้ถูกระงับการใช้งาน"
    );
  }

  const role = String(data.role || "").toLowerCase();

  if (![ROLE_ADMIN, ROLE_ALBUM_MANAGER].includes(role)) {
    throw new HttpsError(
      "permission-denied",
      "บัญชีนี้ไม่มีบทบาทที่ได้รับอนุญาต"
    );
  }

  return {
    id: snapshot.id,
    uid,
    ...data,
    role
  };
}

async function requireUser(request) {
  const uid = await requireAuthenticatedUser(request);
  const profile = await getUserProfile(uid);

  return { uid, profile };
}

function requireAdmin(profile) {
  if (profile.role !== ROLE_ADMIN) {
    throwForbidden("เฉพาะผู้ดูแลระบบเท่านั้นที่ดำเนินการนี้ได้");
  }
}

function requireAdminOrManager(profile) {
  if (![ROLE_ADMIN, ROLE_ALBUM_MANAGER].includes(profile.role)) {
    throwForbidden();
  }
}

async function getOrganization(organizationId) {
  const id = requireString(organizationId, "หน่วยงาน", 256);
  const snapshot = await db.collection(COLLECTIONS.ORGANIZATIONS).doc(id).get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบหน่วยงานที่เลือก");
  }

  return { id: snapshot.id, ...snapshot.data() };
}

async function ensureOrganizationAccess(profile, organizationId) {
  const organization = await getOrganization(organizationId);

  if (
    profile.role === ROLE_ALBUM_MANAGER &&
    profile.organizationId !== organization.id
  ) {
    throwForbidden("คุณไม่สามารถจัดการหน่วยงานอื่นได้");
  }

  return organization;
}

async function getAlbum(albumId) {
  const id = requireString(albumId, "อัลบั้ม", 256);
  const snapshot = await db.collection(COLLECTIONS.ALBUMS).doc(id).get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบอัลบั้มที่ต้องการ");
  }

  return { id: snapshot.id, ...snapshot.data() };
}

async function ensureAlbumAccess(profile, albumId) {
  const album = await getAlbum(albumId);

  if (
    profile.role === ROLE_ALBUM_MANAGER &&
    profile.organizationId !== album.organizationId
  ) {
    throwForbidden("คุณไม่สามารถจัดการอัลบั้มของหน่วยงานอื่นได้");
  }

  return album;
}

async function ensureCategoryExists(categoryId) {
  const id = requireString(categoryId, "หมวดหมู่", 256);
  const snapshot = await db.collection(COLLECTIONS.CATEGORIES).doc(id).get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบหมวดหมู่ที่เลือก");
  }

  return { id: snapshot.id, ...snapshot.data() };
}

/**
 * ================================================================
 * Dashboard initialization
 * ================================================================
 */

async function actionDashboardInit(context) {
  const { profile } = context;

  requireAdminOrManager(profile);

  const organizationSnapshots = profile.role === ROLE_ADMIN
    ? await db.collection(COLLECTIONS.ORGANIZATIONS)
      .orderBy("name")
      .limit(MAX_DASHBOARD_ORGANIZATIONS)
      .get()
    : await db.collection(COLLECTIONS.ORGANIZATIONS)
      .where(admin.firestore.FieldPath.documentId(), "==", profile.organizationId)
      .limit(1)
      .get();

  const organizations = organizationSnapshots.docs.map(snapshot => ({
    id: snapshot.id,
    ...snapshot.data()
  }));

  const organizationMap = new Map(
    organizations.map(organization => [organization.id, organization])
  );

  const categorySnapshots = await db.collection(COLLECTIONS.CATEGORIES)
    .orderBy("name")
    .limit(MAX_DASHBOARD_CATEGORIES)
    .get();

  const categories = categorySnapshots.docs.map(snapshot => ({
    id: snapshot.id,
    ...snapshot.data()
  }));

  let userSnapshots = [];

  if (profile.role === ROLE_ADMIN) {
    const result = await db.collection(COLLECTIONS.USERS)
      .orderBy("createdAt", "desc")
      .limit(MAX_DASHBOARD_USERS)
      .get();

    userSnapshots = result.docs.map(snapshot => ({
      id: snapshot.id,
      ...snapshot.data()
    }));
  }

  let albumQuery = db.collection(COLLECTIONS.ALBUMS)
    .orderBy("updatedAt", "desc")
    .limit(MAX_DASHBOARD_ALBUMS);

  if (profile.role === ROLE_ALBUM_MANAGER) {
    albumQuery = db.collection(COLLECTIONS.ALBUMS)
      .where("organizationId", "==", profile.organizationId)
      .limit(MAX_DASHBOARD_ALBUMS);
  }

  const albumSnapshot = await albumQuery.get();

  const rawAlbums = albumSnapshot.docs.map(snapshot => ({
    id: snapshot.id,
    ...snapshot.data()
  }));

  rawAlbums.sort((a, b) => {
    return timestampMillis(b.updatedAt || b.createdAt) -
      timestampMillis(a.updatedAt || a.createdAt);
  });

  const albumIds = rawAlbums.map(album => album.id);
  const photoMap = new Map();

  /*
   * โหลดรูปของอัลบั้มที่แสดงในแดชบอร์ด
   * ใช้ document ID เป็นตัวเชื่อม เพื่อไม่ให้ข้อมูลข้ามอัลบั้ม
   */
  if (albumIds.length > 0) {
    const photoSnapshots = await db.collection(COLLECTIONS.PHOTOS)
      .where("albumId", "in", albumIds.slice(0, 30))
      .get()
      .catch(async () => null);

    if (photoSnapshots) {
      for (const snapshot of photoSnapshots.docs) {
        const photo = { id: snapshot.id, ...snapshot.data() };

        if (!photoMap.has(photo.albumId)) {
          photoMap.set(photo.albumId, []);
        }

        photoMap.get(photo.albumId).push(photo);
      }
    }

    /*
     * Firestore "in" query รองรับจำนวนค่าจำกัด
     * โหลดส่วนที่เหลือเป็นกลุ่มละ 30 อัลบั้ม
     */
    for (let start = 30; start < albumIds.length; start += 30) {
      const chunk = albumIds.slice(start, start + 30);

      const snapshots = await db.collection(COLLECTIONS.PHOTOS)
        .where("albumId", "in", chunk)
        .get();

      for (const snapshot of snapshots.docs) {
        const photo = { id: snapshot.id, ...snapshot.data() };

        if (!photoMap.has(photo.albumId)) {
          photoMap.set(photo.albumId, []);
        }

        photoMap.get(photo.albumId).push(photo);
      }
    }
  }

  const albums = rawAlbums.map(album => {
    const organization = organizationMap.get(album.organizationId);

    const photos = photoMap.get(album.id) || [];

    return publicAlbum({
      ...album,
      organizationName:
        album.organizationName ||
        organization?.name ||
        "",
      photoCount: album.photoCount ?? photos.length
    }, photos);
  });

  const users = userSnapshots.map(user => publicUser(user, organizationMap));

  const photoCount = albums.reduce((sum, album) => {
    return sum + Number(album.photoCount || 0);
  }, 0);

  const organizationCount = profile.role === ROLE_ADMIN
    ? organizations.length
    : 1;

  const userCount = profile.role === ROLE_ADMIN
    ? users.length
    : undefined;

  const currentProfile = {
    id: profile.id,
    uid: profile.uid,
    fullName: profile.fullName || profile.name || "",
    name: profile.name || profile.fullName || "",
    username: profile.username || "",
    role: profile.role,
    organizationId: profile.organizationId || "",
    organizationName:
      profile.organizationName ||
      organizationMap.get(profile.organizationId)?.name ||
      "",
    disabled: false
  };

  return {
    ok: true,
    appName: APP_NAME,
    version: APP_VERSION,
    profile: currentProfile,
    user: currentProfile,
    organizations: organizations.map(publicOrganization),
    users,
    categories: categories.map(publicCategory),
    albums,
    stats: {
      photoCount,
      albumCount: albums.length,
      organizationCount,
      ...(userCount !== undefined ? { userCount } : {})
    }
  };
}

/**
 * ================================================================
 * Album management
 * ================================================================
 */

async function actionSaveAlbum(context, payload) {
  const { uid, profile } = context;

  requireAdminOrManager(profile);

  const title = requireString(payload.title, "ชื่ออัลบั้ม", MAX_TITLE_LENGTH);
  const description = optionalString(payload.description, MAX_DESCRIPTION_LENGTH);
  const categoryId = requireString(payload.categoryId, "หมวดหมู่", 256);
  const eventDate = normalizeEventDate(payload.eventDate);

  let organizationId = optionalString(payload.organizationId, 256);

  if (profile.role === ROLE_ALBUM_MANAGER) {
    organizationId = profile.organizationId;
  }

  if (!organizationId) {
    throwInvalid("กรุณาเลือกหน่วยงานเจ้าของอัลบั้ม");
  }

  const organization = await ensureOrganizationAccess(profile, organizationId);
  const category = await ensureCategoryExists(categoryId);

  const albumId = optionalString(payload.albumId, 256);
  const albumsCollection = db.collection(COLLECTIONS.ALBUMS);

  const now = nowTimestamp();

  if (albumId) {
    const existing = await ensureAlbumAccess(profile, albumId);

    if (existing.organizationId !== organization.id) {
      throwForbidden("ไม่สามารถย้ายอัลบั้มไปยังหน่วยงานอื่นได้");
    }

    await albumsCollection.doc(albumId).set({
      title,
      description,
      categoryId: category.id,
      categoryName: category.name || "",
      eventDate,
      organizationId: organization.id,
      organizationName: organization.name || "",
      updatedAt: now,
      updatedBy: uid
    }, { merge: true });

    return {
      ok: true,
      albumId,
      id: albumId,
      message: "บันทึกรายละเอียดอัลบั้มแล้ว"
    };
  }

  const reference = albumsCollection.doc();

  const albumData = {
    title,
    description,
    categoryId: category.id,
    categoryName: category.name || "",
    eventDate,
    organizationId: organization.id,
    organizationName: organization.name || "",
    coverUrl: "",
    thumbnailUrl: "",
    photoCount: 0,
    status: ALBUM_STATUS_DRAFT,
    visibility: "public",
    createdBy: uid,
    updatedBy: uid,
    createdAt: now,
    updatedAt: now,
    publishedAt: null
  };

  await reference.set(albumData);

  return {
    ok: true,
    albumId: reference.id,
    id: reference.id,
    message: "สร้างอัลบั้มแล้ว"
  };
}

async function actionPublishAlbum(context, payload) {
  const { uid, profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  const album = await ensureAlbumAccess(profile, albumId);

  const photosSnapshot = await db.collection(COLLECTIONS.PHOTOS)
    .where("albumId", "==", albumId)
    .get();

  const photos = photosSnapshot.docs
    .map(snapshot => ({ id: snapshot.id, ...snapshot.data() }))
    .sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0));

  if (!photos.length) {
    throwInvalid("ไม่สามารถเผยแพร่อัลบั้มที่ไม่มีรูปภาพได้");
  }

  const cover = photos[0];

  await db.collection(COLLECTIONS.ALBUMS).doc(albumId).set({
    status: ALBUM_STATUS_PUBLISHED,
    visibility: "public",
    photoCount: photos.length,
    coverUrl: cover.url || "",
    thumbnailUrl: cover.thumbnailUrl || cover.url || "",
    publishedAt: nowTimestamp(),
    updatedAt: nowTimestamp(),
    updatedBy: uid
  }, { merge: true });

  logger.info("Album published", {
    albumId,
    organizationId: album.organizationId,
    photoCount: photos.length,
    uid
  });

  return {
    ok: true,
    albumId,
    status: ALBUM_STATUS_PUBLISHED,
    photoCount: photos.length,
    message: "เผยแพร่อัลบั้มแล้ว"
  };
}

async function actionDeleteAlbum(context, payload) {
  const { uid, profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  const album = await ensureAlbumAccess(profile, albumId);

  const photoSnapshot = await db.collection(COLLECTIONS.PHOTOS)
    .where("albumId", "==", albumId)
    .get();

  const refs = photoSnapshot.docs.map(snapshot => snapshot.ref);
  refs.push(db.collection(COLLECTIONS.ALBUMS).doc(albumId));

  for (let start = 0; start < refs.length; start += MAX_BATCH_OPERATIONS) {
    const batch = db.batch();
    const chunk = refs.slice(start, start + MAX_BATCH_OPERATIONS);

    for (const ref of chunk) {
      batch.delete(ref);
    }

    await batch.commit();
  }

  logger.info("Album deleted", {
    albumId,
    organizationId: album.organizationId,
    deletedPhotoCount: photoSnapshot.size,
    uid
  });

  return {
    ok: true,
    albumId,
    deletedPhotoCount: photoSnapshot.size,
    message: "ลบอัลบั้มแล้ว"
  };
}

async function actionListAlbumPhotos(context, payload) {
  const { profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  await ensureAlbumAccess(profile, albumId);

  const snapshot = await db.collection(COLLECTIONS.PHOTOS)
    .where("albumId", "==", albumId)
    .get();

  const photos = snapshot.docs
    .map(doc => publicPhoto({ id: doc.id, ...doc.data() }))
    .sort((a, b) => a.order - b.order);

  return { ok: true, albumId, photos };
}

async function actionSaveAlbumPhotos(context, payload) {
  const { uid, profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  const album = await ensureAlbumAccess(profile, albumId);

  if (!Array.isArray(payload.photos)) {
    throwInvalid("รายการรูปภาพไม่ถูกต้อง");
  }

  ensureLimit(payload.photos.length, MAX_PHOTOS_PER_ALBUM, "รูปภาพในอัลบั้ม");

  const photos = payload.photos.map((photo, index) => normalizePhotoInput(photo, index));
  const photoCollection = db.collection(COLLECTIONS.PHOTOS);
  const existingSnapshot = await photoCollection.where("albumId", "==", albumId).get();

  const existingById = new Map(
    existingSnapshot.docs.map(snapshot => [
      snapshot.id,
      { ref: snapshot.ref, data: snapshot.data() }
    ])
  );

  const keepIds = new Set();
  const savedPhotoData = [];
  const now = nowTimestamp();

  for (let index = 0; index < photos.length; index++) {
    const photo = photos[index];
    let reference = null;
    let previous = null;

    /*
     * ใช้ document ID ที่ส่งมาจาก client เฉพาะเมื่อมีเอกสารเดิม
     * ในอัลบั้มนี้จริงเท่านั้น ป้องกันการเขียนทับรูปของอัลบั้มอื่น
     */
    if (photo.id && existingById.has(photo.id)) {
      reference = existingById.get(photo.id).ref;
      previous = existingById.get(photo.id).data;
    } else {
      reference = photoCollection.doc();
    }

    const data = {
      albumId,
      organizationId: album.organizationId,
      url: photo.url,
      thumbnailUrl: photo.thumbnailUrl,
      name: photo.name || `รูปภาพ ${index + 1}`,
      order: index,
      duplicateOf: photo.duplicateOf || null,
      createdAt: previous?.createdAt || now,
      updatedAt: now,
      updatedBy: uid
    };

    keepIds.add(reference.id);
    savedPhotoData.push({
      id: reference.id,
      ...data
    });

    /*
     * ใช้ batch เพื่อจำกัดจำนวนการเขียนต่อ request
     * แบ่งกลุ่มด้านล่างเพื่อไม่ให้เกินขีดจำกัด Firestore
     */
  }

  const operations = [];

  for (const photo of savedPhotoData) {
    operations.push({
      type: "set",
      ref: photoCollection.doc(photo.id),
      data: photo
    });
  }

  for (const existing of existingSnapshot.docs) {
    if (!keepIds.has(existing.id)) {
      operations.push({
        type: "delete",
        ref: existing.ref
      });
    }
  }

  for (let start = 0; start < operations.length; start += MAX_BATCH_OPERATIONS) {
    const batch = db.batch();
    const chunk = operations.slice(start, start + MAX_BATCH_OPERATIONS);

    for (const operation of chunk) {
      if (operation.type === "delete") {
        batch.delete(operation.ref);
      } else {
        batch.set(operation.ref, operation.data, { merge: true });
      }
    }

    await batch.commit();
  }

  const firstPhoto = savedPhotoData[0] || null;

  await db.collection(COLLECTIONS.ALBUMS).doc(albumId).set({
    photoCount: savedPhotoData.length,
    coverUrl: firstPhoto?.url || "",
    thumbnailUrl: firstPhoto?.thumbnailUrl || firstPhoto?.url || "",
    updatedAt: now,
    updatedBy: uid
  }, { merge: true });

  logger.info("Album photos saved", {
    albumId,
    organizationId: album.organizationId,
    photoCount: savedPhotoData.length,
    uid
  });

  return {
    ok: true,
    albumId,
    photoCount: savedPhotoData.length,
    photos: savedPhotoData.map(publicPhoto),
    message: "บันทึกรูปภาพและลำดับรูปแล้ว"
  };
}

async function actionDeletePhotos(context, payload) {
  const { uid, profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  const album = await ensureAlbumAccess(profile, albumId);

  if (!Array.isArray(payload.photoIds) || payload.photoIds.length === 0) {
    throwInvalid("กรุณาเลือกรูปภาพที่ต้องการลบ");
  }

  const photoIds = [...new Set(payload.photoIds.map(id =>
    requireString(id, "รหัสรูปภาพ", 256)
  ))];

  const refs = [];
  for (const photoId of photoIds) {
    const ref = db.collection(COLLECTIONS.PHOTOS).doc(photoId);
    const snapshot = await ref.get();

    if (!snapshot.exists) continue;

    const photo = snapshot.data();

    if (photo.albumId !== albumId) {
      throwForbidden("มีรูปภาพที่ไม่ได้อยู่ในอัลบั้มนี้");
    }

    refs.push(ref);
  }

  for (let start = 0; start < refs.length; start += MAX_BATCH_OPERATIONS) {
    const batch = db.batch();
    for (const ref of refs.slice(start, start + MAX_BATCH_OPERATIONS)) {
      batch.delete(ref);
    }
    await batch.commit();
  }

  const remaining = await db.collection(COLLECTIONS.PHOTOS)
    .where("albumId", "==", albumId)
    .get();

  const remainingPhotos = remaining.docs
    .map(doc => ({ id: doc.id, ...doc.data() }))
    .sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0));

  const batch = db.batch();

  remainingPhotos.forEach((photo, index) => {
    batch.set(db.collection(COLLECTIONS.PHOTOS).doc(photo.id), {
      order: index,
      updatedAt: nowTimestamp(),
      updatedBy: uid
    }, { merge: true });
  });

  batch.set(db.collection(COLLECTIONS.ALBUMS).doc(albumId), {
    photoCount: remainingPhotos.length,
    coverUrl: remainingPhotos[0]?.url || "",
    thumbnailUrl: remainingPhotos[0]?.thumbnailUrl || remainingPhotos[0]?.url || "",
    updatedAt: nowTimestamp(),
    updatedBy: uid
  }, { merge: true });

  await batch.commit();

  return {
    ok: true,
    albumId,
    deletedCount: refs.length,
    message: "ลบรูปภาพแล้ว"
  };
}

async function actionReorderPhotos(context, payload) {
  const { uid, profile } = context;
  requireAdminOrManager(profile);

  const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
  await ensureAlbumAccess(profile, albumId);

  if (!Array.isArray(payload.photoIds)) {
    throwInvalid("รายการลำดับรูปภาพไม่ถูกต้อง");
  }

  ensureLimit(payload.photoIds.length, MAX_PHOTOS_PER_ALBUM, "รูปภาพในอัลบั้ม");

  const photoIds = payload.photoIds.map(id => requireString(id, "รหัสรูปภาพ", 256));

  if (new Set(photoIds).size !== photoIds.length) {
    throwInvalid("รายการรูปภาพมีรหัสซ้ำกัน");
  }

  const refs = photoIds.map(id => db.collection(COLLECTIONS.PHOTOS).doc(id));
  const snapshots = refs.length ? await db.getAll(...refs) : [];

  for (let i = 0; i < snapshots.length; i++) {
    const snapshot = snapshots[i];

    if (!snapshot.exists || snapshot.data().albumId !== albumId) {
      throwForbidden("รายการมีรูปภาพที่ไม่ได้อยู่ในอัลบั้มนี้");
    }
  }

  for (let start = 0; start < refs.length; start += MAX_BATCH_OPERATIONS) {
    const batch = db.batch();

    for (let i = start; i < Math.min(start + MAX_BATCH_OPERATIONS, refs.length); i++) {
      batch.set(refs[i], {
        order: i,
        updatedAt: nowTimestamp(),
        updatedBy: uid
      }, { merge: true });
    }

    await batch.commit();
  }

  const first = snapshots[0]?.data();

  await db.collection(COLLECTIONS.ALBUMS).doc(albumId).set({
    coverUrl: first?.url || "",
    thumbnailUrl: first?.thumbnailUrl || first?.url || "",
    photoCount: photoIds.length,
    updatedAt: nowTimestamp(),
    updatedBy: uid
  }, { merge: true });

  return {
    ok: true,
    albumId,
    order: photoIds,
    message: "จัดเรียงรูปภาพแล้ว"
  };
}

/**
 * ================================================================
 * Organization management
 * ================================================================
 */

async function actionSaveOrganization(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const name = requireString(payload.name, "ชื่อหน่วยงาน", MAX_NAME_LENGTH);
  const logoUrl = payload.logoUrl
    ? normalizeHttpUrl(payload.logoUrl, "URL โลโก้")
    : "";

  const organizationId = optionalString(payload.organizationId, 256);
  const now = nowTimestamp();
  const collection = db.collection(COLLECTIONS.ORGANIZATIONS);

  if (organizationId) {
    const ref = collection.doc(organizationId);
    const snapshot = await ref.get();

    if (!snapshot.exists) {
      throwNotFound("ไม่พบหน่วยงานที่ต้องการแก้ไข");
    }

    await ref.set({
      name,
      logoUrl: logoUrl || snapshot.data().logoUrl || "",
      updatedAt: now,
      updatedBy: uid
    }, { merge: true });

    return {
      ok: true,
      organizationId,
      id: organizationId,
      message: "แก้ไขหน่วยงานแล้ว"
    };
  }

  const reference = collection.doc();

  await reference.set({
    name,
    logoUrl,
    createdBy: uid,
    updatedBy: uid,
    createdAt: now,
    updatedAt: now
  });

  return {
    ok: true,
    organizationId: reference.id,
    id: reference.id,
    message: "เพิ่มหน่วยงานแล้ว"
  };
}

async function actionDeleteOrganization(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const organizationId = requireString(payload.organizationId, "หน่วยงาน", 256);
  const reference = db.collection(COLLECTIONS.ORGANIZATIONS).doc(organizationId);
  const snapshot = await reference.get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบหน่วยงานที่ต้องการลบ");
  }

  const [userSnapshot, albumSnapshot] = await Promise.all([
    db.collection(COLLECTIONS.USERS)
      .where("organizationId", "==", organizationId)
      .limit(1)
      .get(),
    db.collection(COLLECTIONS.ALBUMS)
      .where("organizationId", "==", organizationId)
      .limit(1)
      .get()
  ]);

  if (!userSnapshot.empty || !albumSnapshot.empty) {
    throw new HttpsError(
      "failed-precondition",
      "ไม่สามารถลบหน่วยงานที่ยังมีผู้ใช้งานหรืออัลบั้มอยู่ได้ กรุณาย้ายหรือลบข้อมูลที่เกี่ยวข้องก่อน"
    );
  }

  await reference.delete();

  logger.info("Organization deleted", { organizationId, uid });

  return {
    ok: true,
    organizationId,
    message: "ลบหน่วยงานแล้ว"
  };
}

/**
 * ================================================================
 * Category management
 * ================================================================
 */

async function actionSaveCategory(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const name = requireString(payload.name, "ชื่อหมวดหมู่", MAX_CATEGORY_LENGTH);
  const categoryId = optionalString(payload.categoryId, 256);
  const collection = db.collection(COLLECTIONS.CATEGORIES);
  const now = nowTimestamp();

  if (categoryId) {
    const ref = collection.doc(categoryId);
    const snapshot = await ref.get();

    if (!snapshot.exists) {
      throwNotFound("ไม่พบหมวดหมู่ที่ต้องการแก้ไข");
    }

    await ref.set({
      name,
      updatedAt: now,
      updatedBy: uid
    }, { merge: true });

    /*
     * ปรับชื่อหมวดหมู่ที่เก็บไว้ในอัลบั้มด้วย
     */
    const albumSnapshot = await db.collection(COLLECTIONS.ALBUMS)
      .where("categoryId", "==", categoryId)
      .get();

    for (let start = 0; start < albumSnapshot.docs.length; start += MAX_BATCH_OPERATIONS) {
      const batch = db.batch();

      for (const albumDoc of albumSnapshot.docs.slice(start, start + MAX_BATCH_OPERATIONS)) {
        batch.set(albumDoc.ref, {
          categoryName: name,
          updatedAt: now
        }, { merge: true });
      }

      await batch.commit();
    }

    return {
      ok: true,
      categoryId,
      id: categoryId,
      message: "แก้ไขหมวดหมู่แล้ว"
    };
  }

  const reference = collection.doc();

  await reference.set({
    name,
    createdBy: uid,
    updatedBy: uid,
    createdAt: now,
    updatedAt: now
  });

  return {
    ok: true,
    categoryId: reference.id,
    id: reference.id,
    message: "เพิ่มหมวดหมู่แล้ว"
  };
}

async function actionDeleteCategory(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const categoryId = requireString(payload.categoryId, "หมวดหมู่", 256);
  const reference = db.collection(COLLECTIONS.CATEGORIES).doc(categoryId);
  const snapshot = await reference.get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบหมวดหมู่ที่ต้องการลบ");
  }

  const albumSnapshot = await db.collection(COLLECTIONS.ALBUMS)
    .where("categoryId", "==", categoryId)
    .limit(1)
    .get();

  if (!albumSnapshot.empty) {
    throw new HttpsError(
      "failed-precondition",
      "ไม่สามารถลบหมวดหมู่ที่ยังถูกใช้งานในอัลบั้มได้"
    );
  }

  await reference.delete();

  logger.info("Category deleted", { categoryId, uid });

  return {
    ok: true,
    categoryId,
    message: "ลบหมวดหมู่แล้ว"
  };
}

/**
 * ================================================================
 * User management
 * ================================================================
 */

async function ensureUsernameAvailable(username, exceptUid = "") {
  const normalized = normalizeUsername(username);

  const snapshot = await db.collection(COLLECTIONS.USERS)
    .where("username", "==", normalized)
    .limit(2)
    .get();

  const conflict = snapshot.docs.some(doc => doc.id !== exceptUid);

  if (conflict) {
    throwConflict("ชื่อผู้ใช้นี้ถูกใช้แล้ว กรุณาเลือกชื่ออื่น");
  }

  return normalized;
}

async function actionCreateUser(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const fullName = requireString(payload.fullName, "ชื่อ-สกุล", 150);
  const username = await ensureUsernameAvailable(payload.username);
  const organizationId = requireString(payload.organizationId, "หน่วยงาน", 256);
  const organization = await getOrganization(organizationId);

  /*
   * หาก Frontend ส่ง password มา ระบบจะใช้รหัสผ่านนั้น
   * หากไม่ส่ง ระบบจะสร้างรหัสผ่านเริ่มต้น GF + เลข 6 หลัก
   *
   * การสร้างบัญชีจริงต้องทำผ่าน Firebase Admin SDK
   * และจะไม่บันทึกรหัสผ่านแบบข้อความธรรมดาใน Firestore
   */
  const generatedPassword = payload.password
    ? null
    : makeGeneratedPassword();

  const password = validatePassword(payload.password || generatedPassword);
  const email = usernameToAuthEmail(username);

  let authUser = null;

  try {
    authUser = await auth.createUser({
      email,
      password,
      displayName: fullName,
      disabled: false,
      emailVerified: true
    });
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throwConflict("ชื่อผู้ใช้นี้มีบัญชี Firebase อยู่แล้ว");
    }

    if (error.code === "auth/invalid-password") {
      throwInvalid("รหัสผ่านไม่ผ่านเงื่อนไขความปลอดภัยของ Firebase");
    }

    logger.error("Unable to create Firebase Auth user", {
      code: error.code || "unknown"
    });

    throwFailed("สร้างบัญชีเข้าสู่ระบบไม่สำเร็จ");
  }

  const now = nowTimestamp();

  try {
    await db.collection(COLLECTIONS.USERS).doc(authUser.uid).set({
      uid: authUser.uid,
      fullName,
      name: fullName,
      username,
      email,
      role: ROLE_ALBUM_MANAGER,
      organizationId: organization.id,
      organizationName: organization.name || "",
      disabled: false,
      createdBy: uid,
      updatedBy: uid,
      createdAt: now,
      updatedAt: now
    });
  } catch (error) {
    /*
     * หากบันทึกโปรไฟล์ล้มเหลว ให้ลบบัญชี Auth ที่เพิ่งสร้าง
     * เพื่อลดโอกาสเกิดบัญชีที่เข้าสู่ระบบได้แต่ไม่มีสิทธิ์
     */
    try {
      await auth.deleteUser(authUser.uid);
    } catch (cleanupError) {
      logger.error("Failed to clean up orphaned Auth user", {
        uid: authUser.uid,
        code: cleanupError.code || "unknown"
      });
    }

    throw error;
  }

  logger.info("Album manager created", {
    uid: authUser.uid,
    username,
    organizationId,
    createdBy: uid
  });

  return {
    ok: true,
    userId: authUser.uid,
    id: authUser.uid,
    username,
    generatedPassword: generatedPassword || undefined,
    message: "เพิ่มผู้ใช้งานแล้ว"
  };
}

async function actionUpdateUser(context, payload) {
  const { uid, profile } = context;
  requireAdmin(profile);

  const userId = requireString(payload.userId, "ผู้ใช้งาน", 256);
  const fullName = requireString(payload.fullName, "ชื่อ-สกุล", 150);
  const organizationId = requireString(payload.organizationId, "หน่วยงาน", 256);

  const organization = await getOrganization(organizationId);
  const reference = db.collection(COLLECTIONS.USERS).doc(userId);
  const snapshot = await reference.get();

  if (!snapshot.exists) {
    throwNotFound("ไม่พบผู้ใช้งานที่ต้องการแก้ไข");
  }

  const existing = snapshot.data();

  if (existing.role === ROLE_ADMIN && existing.uid !== uid) {
    throwForbidden("ไม่สามารถแก้ไขบัญชีผู้ดูแลระบบอื่นผ่านเมนูนี้ได้");
  }

  const update = {
    fullName,
    name: fullName,
    organizationId: organization.id,
    organizationName: organization.name || "",
    updatedAt: nowTimestamp(),
    updatedBy: uid
  };

  if (payload.password !== undefined && payload.password !== null && payload.password !== "") {
    const password = validatePassword(payload.password);

    try {
      await auth.updateUser(userId, {
        password,
        displayName: fullName
      });
    } catch (error) {
      logger.error("Unable to update user password", {
        uid: userId,
        code: error.code || "unknown"
      });

      throwFailed("เปลี่ยนรหัสผ่านไม่สำเร็จ");
    }
  } else {
    try {
      await auth.updateUser(userId, {
        displayName: fullName
      });
    } catch (error) {
      logger.error("Unable to update user display name", {
        uid: userId,
        code: error.code || "unknown"
      });

      throwFailed("แก้ไขข้อมูลบัญชีเข้าสู่ระบบไม่สำเร็จ");
    }
  }

  await reference.set(update, { merge: true });

  return {
    ok: true,
    userId,
    message: "แก้ไขผู้ใช้งานแล้ว"
  };
}

/**
 * ================================================================
 * ImgBB image upload
 * ================================================================
 */

function validateBase64Image(base64) {
  if (typeof base64 !== "string" || !base64.length) {
    throwInvalid("ไม่พบข้อมูลรูปภาพ");
  }

  if (base64.length > MAX_BASE64_LENGTH) {
    throw new HttpsError(
      "resource-exhausted",
      "รูปภาพมีขนาดใหญ่เกินกำหนด กรุณาลดขนาดไฟล์แล้วลองใหม่"
    );
  }

  const normalized = base64.replace(/\s/g, "");

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throwInvalid("ข้อมูลรูปภาพ Base64 ไม่ถูกต้อง");
  }

  const buffer = Buffer.from(normalized, "base64");

  if (!buffer.length) {
    throwInvalid("ไม่สามารถอ่านข้อมูลรูปภาพได้");
  }

  if (buffer.length > MAX_IMAGE_BYTES) {
    throw new HttpsError(
      "resource-exhausted",
      `รูปภาพต้องมีขนาดไม่เกิน ${Math.floor(MAX_IMAGE_BYTES / 1024 / 1024)} MB`
    );
  }

  return {
    base64: normalized,
    buffer
  };
}

async function sendImageToImgBB({ apiKey, base64, fileName }) {
  const params = new URLSearchParams();

  params.set("key", apiKey);
  params.set("image", base64);
  params.set("name", fileName.replace(/[^\w.-]/g, "_").slice(0, 180));

  let response;

  try {
    response = await fetch(IMG_BB_UPLOAD_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params,
      signal: AbortSignal.timeout(120000)
    });
  } catch (error) {
    logger.error("ImgBB network request failed", {
      message: error.message || "network error"
    });

    throw new HttpsError(
      "unavailable",
      "ไม่สามารถเชื่อมต่อบริการอัปโหลดรูปภาพได้ กรุณาลองใหม่"
    );
  }

  let body;

  try {
    body = await response.json();
  } catch {
    throw new HttpsError(
      "unavailable",
      "บริการอัปโหลดรูปภาพส่งข้อมูลกลับมาไม่ถูกต้อง"
    );
  }

  if (!response.ok || body?.success !== true || !body?.data?.url) {
    logger.error("ImgBB upload rejected", {
      status: response.status,
      error: body?.error?.message || "upload rejected"
    });

    throw new HttpsError(
      "internal",
      body?.error?.message || "อัปโหลดรูปภาพไปยัง ImgBB ไม่สำเร็จ"
    );
  }

  return {
    url: body.data.url,
    displayUrl: body.data.display_url || body.data.url,
    thumbnailUrl: body.data.thumb?.url || body.data.medium?.url || body.data.url,
    deleteUrl: body.data.delete_url || "",
    imageId: body.data.id || "",
    fileName: body.data.image?.filename || "",
    mimeType: body.data.image?.mime || "",
    size: Number(body.data.size || 0)
  };
}

async function actionUploadImage(request) {
  const { uid, profile } = await requireUser(request);
  requireAdminOrManager(profile);

  const payload = requireObject(request.data || {}, "ข้อมูลอัปโหลด");

  const purpose = requireString(payload.purpose, "ประเภทการอัปโหลด", 20)
    .toLowerCase();

  if (!["photo", "logo"].includes(purpose)) {
    throwInvalid("ประเภทการอัปโหลดไม่ถูกต้อง");
  }

  if (purpose === "logo") {
    requireAdmin(profile);
  }

  const fileName = requireString(payload.fileName, "ชื่อไฟล์", 255);
  const mimeType = normalizeImageMimeType(payload.mimeType);
  const checkedImage = validateBase64Image(payload.base64);

  let album = null;

  if (purpose === "photo") {
    const albumId = requireString(payload.albumId, "อัลบั้ม", 256);
    album = await ensureAlbumAccess(profile, albumId);
  }

  const apiKey = IMGBB_API_KEY.value();

  if (!apiKey || apiKey.trim().length < 10) {
    logger.error("ImgBB API key is missing");
    throwFailed("ยังไม่ได้ตั้งค่า ImgBB API key ใน Secret Manager");
  }

  const result = await sendImageToImgBB({
    apiKey,
    base64: checkedImage.base64,
    fileName
  });

  logger.info("Image uploaded to ImgBB", {
    uid,
    purpose,
    albumId: album?.id || null,
    fileName,
    size: checkedImage.buffer.length
  });

  /*
   * ฟังก์ชันนี้ส่ง URL กลับไปให้ dashboard.html
   * การสร้าง/ปรับลำดับ photo document ทำใน saveAlbumPhotos
   * เพื่อให้การบันทึกรายการรูปและลำดับทำงานร่วมกัน
   */
  return {
    ok: true,
    purpose,
    url: result.url,
    imageUrl: result.url,
    displayUrl: result.displayUrl,
    thumbnailUrl: result.thumbnailUrl,
    imageId: result.imageId,
    fileName: result.fileName || fileName,
    mimeType: result.mimeType || mimeType,
    size: result.size,
    message: "อัปโหลดรูปภาพสำเร็จ"
  };
}

/**
 * ================================================================
 * One-time administrator bootstrap
 * ================================================================
 *
 * Invoke this callable only during initial setup.
 *
 * Required payload:
 * {
 *   "bootstrapKey": "THE_SECRET_VALUE",
 *   "username": "your_admin_username",
 *   "password": "your_strong_password",
 *   "fullName": "Administrator"
 * }
 *
 * The BOOTSTRAP_KEY must be configured as a Firebase Secret.
 *
 * This function refuses to create an administrator if an admin
 * profile already exists. Keep the secret private.
 * ================================================================
 */

async function actionBootstrapAdmin(request) {
  const payload = requireObject(request.data || {}, "ข้อมูล Bootstrap");

  const suppliedKey = requireString(payload.bootstrapKey, "Bootstrap key", 512);
  const expectedKey = BOOTSTRAP_KEY.value();

  if (!expectedKey || !constantTimeSecretCompare(suppliedKey, expectedKey)) {
    throwForbidden("Bootstrap key ไม่ถูกต้อง");
  }

  const adminSnapshot = await db.collection(COLLECTIONS.USERS)
    .where("role", "==", ROLE_ADMIN)
    .limit(1)
    .get();

  if (!adminSnapshot.empty) {
    throw new HttpsError(
      "failed-precondition",
      "มีบัญชีผู้ดูแลระบบอยู่แล้ว ไม่สามารถใช้ Bootstrap ซ้ำได้"
    );
  }

  const username = await ensureUsernameAvailable(payload.username);
  const fullName = requireString(payload.fullName || "ผู้ดูแลระบบ", "ชื่อ-สกุล", 150);
  const password = validatePassword(payload.password);
  const email = usernameToAuthEmail(username);

  let authUser;

  try {
    authUser = await auth.createUser({
      email,
      password,
      displayName: fullName,
      emailVerified: true,
      disabled: false
    });
  } catch (error) {
    if (error.code === "auth/email-already-exists") {
      throwConflict("ชื่อผู้ใช้นี้มีบัญชี Firebase อยู่แล้ว");
    }

    logger.error("Bootstrap Auth account creation failed", {
      code: error.code || "unknown"
    });

    throwFailed("สร้างบัญชีผู้ดูแลระบบไม่สำเร็จ");
  }

  try {
    await db.collection(COLLECTIONS.USERS).doc(authUser.uid).set({
      uid: authUser.uid,
      fullName,
      name: fullName,
      username,
      email,
      role: ROLE_ADMIN,
      organizationId: "",
      organizationName: "ผู้ดูแลระบบ",
      disabled: false,
      createdBy: "bootstrap",
      updatedBy: "bootstrap",
      createdAt: nowTimestamp(),
      updatedAt: nowTimestamp()
    });
  } catch (error) {
    try {
      await auth.deleteUser(authUser.uid);
    } catch (cleanupError) {
      logger.error("Bootstrap cleanup failed", {
        uid: authUser.uid,
        code: cleanupError.code || "unknown"
      });
    }

    throw error;
  }

  logger.warn("Initial administrator created", {
    uid: authUser.uid,
    username
  });

  return {
    ok: true,
    userId: authUser.uid,
    username,
    message: "สร้างบัญชีผู้ดูแลระบบเริ่มต้นแล้ว"
  };
}

/**
 * ================================================================
 * dashboardApi action router
 * ================================================================
 */

const API_ACTIONS = Object.freeze({
  dashboardInit: actionDashboardInit,
  saveAlbum: actionSaveAlbum,
  publishAlbum: actionPublishAlbum,
  deleteAlbum: actionDeleteAlbum,
  listAlbumPhotos: actionListAlbumPhotos,
  saveAlbumPhotos: actionSaveAlbumPhotos,
  deletePhotos: actionDeletePhotos,
  reorderPhotos: actionReorderPhotos,
  saveOrganization: actionSaveOrganization,
  deleteOrganization: actionDeleteOrganization,
  saveCategory: actionSaveCategory,
  deleteCategory: actionDeleteCategory,
  createUser: actionCreateUser,
  updateUser: actionUpdateUser
});

exports.dashboardApi = onCall(
  {
    region: REGION,
    timeoutSeconds: 300,
    memory: "1GiB",
    enforceAppCheck: false
  },
  async (request) => {
    const payload = requireObject(request.data || {}, "ข้อมูลคำขอ");
    const action = requireString(payload.action, "action", 100);

    const handler = API_ACTIONS[action];

    if (typeof handler !== "function") {
      throw new HttpsError(
        "invalid-argument",
        `ไม่รู้จักคำสั่ง ${action}`
      );
    }

    const context = await requireUser(request);

    try {
      const result = await handler(context, payload);

      return {
        ok: true,
        ...result
      };
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error("dashboardApi action failed", {
        action,
        uid: context.uid,
        role: context.profile.role,
        code: error.code || "unknown",
        message: error.message || "unknown error"
      });

      throw new HttpsError(
        "internal",
        "ระบบไม่สามารถดำเนินการได้ กรุณาลองใหม่อีกครั้ง"
      );
    }
  }
);

/**
 * ================================================================
 * Image upload callable
 * ================================================================
 */

exports.uploadImage = onCall(
  {
    region: REGION,
    timeoutSeconds: 180,
    memory: "1GiB",
    secrets: [IMGBB_API_KEY],
    enforceAppCheck: false
  },
  async (request) => {
    try {
      return await actionUploadImage(request);
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error("uploadImage failed", {
        uid: request.auth?.uid || null,
        code: error.code || "unknown",
        message: error.message || "unknown error"
      });

      throw new HttpsError(
        "internal",
        "อัปโหลดรูปภาพไม่สำเร็จ กรุณาลองใหม่"
      );
    }
  }
);

/**
 * ================================================================
 * Bootstrap callable
 * ================================================================
 */

exports.bootstrapAdmin = onCall(
  {
    region: REGION,
    timeoutSeconds: 120,
    memory: "512MiB",
    secrets: [BOOTSTRAP_KEY],
    enforceAppCheck: false
  },
  async (request) => {
    try {
      return await actionBootstrapAdmin(request);
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error("bootstrapAdmin failed", {
        code: error.code || "unknown",
        message: error.message || "unknown error"
      });

      throw new HttpsError(
        "internal",
        "สร้างบัญชีผู้ดูแลระบบไม่สำเร็จ"
      );
    }
  }
);
