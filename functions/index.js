'use strict';

/* ============================================================================
 * ActiGallery - Firebase Cloud Functions Backend
 * File: functions/index.js
 * Version: 3.0.0
 *
 * Platform:
 *   - Firebase Cloud Functions v2
 *   - Firebase Authentication
 *   - Cloud Firestore
 *   - ImgBB Image Hosting
 *   - Node.js 20
 *
 * Region:
 *   asia-southeast1
 *
 * Required Secret Manager secrets:
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
 * Roles:
 *   admin
 *   album_manager
 *
 * Important:
 *   - This backend never stores user passwords in Firestore.
 *   - User passwords are managed by Firebase Authentication.
 *   - All management operations require Firebase Authentication.
 *   - Album managers can only manage their own organization's content.
 *   - Image uploads use ImgBB.
 *   - Albums are published after the requested save/upload workflow
 *     completes successfully.
 * ========================================================================== */

const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const crypto = require('node:crypto');

admin.initializeApp();

const db = admin.firestore();
const auth = admin.auth();
const FieldValue = admin.firestore.FieldValue;

const IMGBB_API_KEY = defineSecret('IMGBB_API_KEY');
const BOOTSTRAP_KEY = defineSecret('BOOTSTRAP_KEY');

const REGION = 'asia-southeast1';

const CONFIG = Object.freeze({
  APP_NAME: 'ActiGallery',
  VERSION: '3.0.0',
  REGION,

  COLLECTIONS: Object.freeze({
    USERS: 'users',
    ORGANIZATIONS: 'organizations',
    CATEGORIES: 'categories',
    ALBUMS: 'albums',
    PHOTOS: 'photos'
  }),

  ROLES: Object.freeze({
    ADMIN: 'admin',
    ALBUM_MANAGER: 'album_manager'
  }),

  USER_STATUS: Object.freeze({
    ACTIVE: 'active',
    DISABLED: 'disabled'
  }),

  ALBUM_STATUS: Object.freeze({
    DRAFT: 'draft',
    PUBLISHED: 'published',
    PRIVATE: 'private'
  }),

  PHOTO_STATUS: Object.freeze({
    READY: 'ready',
    DELETED: 'deleted'
  }),

  IMAGE: Object.freeze({
    MAX_BYTES: 7 * 1024 * 1024,
    ALLOWED_MIME_TYPES: [
      'image/jpeg',
      'image/png',
      'image/webp',
      'image/gif'
    ],
    IMGBB_TIMEOUT_MS: 60000
  }),

  USERNAME_EMAIL_DOMAIN: 'users.actigallery.app',

  MAX_BATCH_OPERATIONS: 400,
  MAX_LIST_LIMIT: 500,
  MAX_PHOTOS_PER_REQUEST: 100,
  MAX_TEXT_LENGTH: 5000
});

/* ============================================================================
 * GENERAL UTILITIES
 * ========================================================================== */

function fail(code, message, details) {
  throw new HttpsError(code, message, details);
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value)
  );
}

function cleanString(value, maxLength = CONFIG.MAX_TEXT_LENGTH) {
  if (typeof value !== 'string') {
    return '';
  }

  return value.trim().slice(0, maxLength);
}

function requiredString(value, fieldName, maxLength = 500) {
  const result = cleanString(value, maxLength);

  if (!result) {
    fail('invalid-argument', `กรุณาระบุ${fieldName}`);
  }

  return result;
}

function optionalString(value, maxLength = 5000) {
  return cleanString(value, maxLength);
}

function normalizeUsername(value) {
  return cleanString(value, 64).toLowerCase();
}

function usernameToEmail(username) {
  const normalized = normalizeUsername(username);

  if (!/^[a-z0-9._-]{3,64}$/.test(normalized)) {
    fail(
      'invalid-argument',
      'ชื่อผู้ใช้ต้องมีความยาว 3–64 ตัวอักษร และใช้ภาษาอังกฤษ ตัวเลข จุด ขีดกลาง หรือขีดล่าง'
    );
  }

  return `${normalized}@${CONFIG.USERNAME_EMAIL_DOMAIN}`;
}

function normalizeMimeType(value) {
  return cleanString(value, 100).toLowerCase();
}

function normalizeRole(value) {
  const role = cleanString(value, 50).toLowerCase();

  if (
    role !== CONFIG.ROLES.ADMIN &&
    role !== CONFIG.ROLES.ALBUM_MANAGER
  ) {
    fail('invalid-argument', 'ประเภทผู้ใช้ไม่ถูกต้อง');
  }

  return role;
}

function normalizeStatus(value, allowedValues, fieldName) {
  const status = cleanString(value, 50).toLowerCase();

  if (!allowedValues.includes(status)) {
    fail('invalid-argument', `${fieldName}ไม่ถูกต้อง`);
  }

  return status;
}

function makeId() {
  return crypto.randomUUID();
}

function makeInitialPassword(sequenceNumber) {
  return `GF${String(sequenceNumber).padStart(6, '0')}`;
}

function validateDocumentId(value, fieldName = 'รหัสข้อมูล') {
  const id = requiredString(value, fieldName, 200);

  if (
    id.includes('/') ||
    id === '.' ||
    id === '..'
  ) {
    fail('invalid-argument', `${fieldName}ไม่ถูกต้อง`);
  }

  return id;
}

function safeInteger(value, fallback = 0) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return fallback;
  }

  return Math.trunc(number);
}

function getCollection(name) {
  return db.collection(name);
}

function serverTimestamp() {
  return FieldValue.serverTimestamp();
}

function nowMilliseconds() {
  return Date.now();
}

function getActorUid(request) {
  if (!request.auth || !request.auth.uid) {
    fail('unauthenticated', 'กรุณาเข้าสู่ระบบก่อนใช้งาน');
  }

  return request.auth.uid;
}

function getRequestData(request) {
  if (!isPlainObject(request.data)) {
    fail('invalid-argument', 'รูปแบบข้อมูลที่ส่งมาไม่ถูกต้อง');
  }

  return request.data;
}

function getAction(data) {
  return requiredString(data.action, 'คำสั่ง', 100);
}

function assertStringArray(value, fieldName, maxItems = 100) {
  if (!Array.isArray(value)) {
    fail('invalid-argument', `${fieldName}ต้องเป็นรายการ`);
  }

  if (value.length > maxItems) {
    fail(
      'invalid-argument',
      `${fieldName}มีจำนวนรายการมากเกินไป`
    );
  }

  return value.map((item) => {
    return requiredString(item, fieldName, 200);
  });
}

function chunkArray(items, size) {
  const result = [];

  for (let i = 0; i < items.length; i += size) {
    result.push(items.slice(i, i + size));
  }

  return result;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* ============================================================================
 * AUTHENTICATION AND AUTHORIZATION
 * ========================================================================== */

async function getUserProfile(uid) {
  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.USERS
  ).doc(uid).get();

  if (!snapshot.exists) {
    fail(
      'permission-denied',
      'ไม่พบข้อมูลผู้ใช้ในระบบ กรุณาติดต่อผู้ดูแลระบบ'
    );
  }

  const profile = snapshot.data();

  if (profile.status === CONFIG.USER_STATUS.DISABLED) {
    fail(
      'permission-denied',
      'บัญชีผู้ใช้นี้ถูกระงับการใช้งาน'
    );
  }

  return {
    uid,
    ...profile
  };
}

async function requireSignedIn(request) {
  const uid = getActorUid(request);

  const profile = await getUserProfile(uid);

  return {
    uid,
    profile
  };
}

async function requireAdmin(request) {
  const actor = await requireSignedIn(request);

  if (actor.profile.role !== CONFIG.ROLES.ADMIN) {
    fail(
      'permission-denied',
      'คำสั่งนี้อนุญาตเฉพาะผู้ดูแลระบบ'
    );
  }

  return actor;
}

async function requireAlbumManagerOrAdmin(request) {
  const actor = await requireSignedIn(request);

  const role = actor.profile.role;

  if (
    role !== CONFIG.ROLES.ADMIN &&
    role !== CONFIG.ROLES.ALBUM_MANAGER
  ) {
    fail(
      'permission-denied',
      'คุณไม่มีสิทธิ์จัดการอัลบั้ม'
    );
  }

  return actor;
}

function isAdmin(actor) {
  return actor.profile.role === CONFIG.ROLES.ADMIN;
}

function getOrganizationId(actor) {
  return cleanString(actor.profile.organizationId, 200);
}

function assertOrganizationScope(actor, organizationId) {
  if (isAdmin(actor)) {
    return;
  }

  const actorOrganizationId = getOrganizationId(actor);

  if (!actorOrganizationId) {
    fail(
      'failed-precondition',
      'บัญชีผู้ใช้ยังไม่ได้กำหนดองค์กร'
    );
  }

  if (actorOrganizationId !== organizationId) {
    fail(
      'permission-denied',
      'คุณไม่มีสิทธิ์เข้าถึงข้อมูลขององค์กรอื่น'
    );
  }
}

async function getOrganization(organizationId) {
  const id = validateDocumentId(
    organizationId,
    'รหัสองค์กร'
  );

  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.ORGANIZATIONS
  ).doc(id).get();

  if (!snapshot.exists) {
    fail('not-found', 'ไม่พบองค์กรที่ระบุ');
  }

  return {
    id: snapshot.id,
    ...snapshot.data()
  };
}

async function getAlbum(albumId) {
  const id = validateDocumentId(
    albumId,
    'รหัสอัลบั้ม'
  );

  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  ).doc(id).get();

  if (!snapshot.exists) {
    fail('not-found', 'ไม่พบอัลบั้มที่ระบุ');
  }

  return {
    id: snapshot.id,
    ...snapshot.data()
  };
}

async function requireAlbumAccess(actor, albumId) {
  const album = await getAlbum(albumId);

  assertOrganizationScope(
    actor,
    cleanString(album.organizationId, 200)
  );

  return album;
}

/* ============================================================================
 * SERIALIZATION
 * ========================================================================== */

function serializeDocument(snapshot) {
  const data = snapshot.data() || {};

  return {
    id: snapshot.id,
    ...data
  };
}

function serializeForClient(value) {
  if (value === null || value === undefined) {
    return value === undefined ? null : null;
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (
    value &&
    typeof value.toDate === 'function'
  ) {
    return value.toDate().toISOString();
  }

  if (Array.isArray(value)) {
    return value.map(serializeForClient);
  }

  if (isPlainObject(value)) {
    const result = {};

    for (const [key, item] of Object.entries(value)) {
      result[key] = serializeForClient(item);
    }

    return result;
  }

  return value;
}

function serializeProfile(profile) {
  const result = { ...profile };

  delete result.password;
  delete result.passwordHash;
  delete result.resetToken;

  return serializeForClient(result);
}

/* ============================================================================
 * INPUT VALIDATION
 * ========================================================================== */

function validateImageMimeType(mimeType) {
  const normalized = normalizeMimeType(mimeType);

  if (
    !CONFIG.IMAGE.ALLOWED_MIME_TYPES.includes(normalized)
  ) {
    fail(
      'invalid-argument',
      'รองรับเฉพาะรูปภาพ JPEG, PNG, WEBP และ GIF'
    );
  }

  return normalized;
}

function validateImageBase64(base64Value) {
  const input = requiredString(
    base64Value,
    'ข้อมูลรูปภาพ',
    CONFIG.IMAGE.MAX_BYTES * 2
  );

  let base64 = input;

  const dataUriMatch = input.match(
    /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/
  );

  if (dataUriMatch) {
    base64 = dataUriMatch[2];
  }

  base64 = base64.replace(/\s/g, '');

  if (
    !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) ||
    base64.length % 4 === 1
  ) {
    fail('invalid-argument', 'ข้อมูลรูปภาพไม่ถูกต้อง');
  }

  const estimatedBytes = Math.floor(
    (base64.length * 3) / 4
  );

  if (estimatedBytes > CONFIG.IMAGE.MAX_BYTES) {
    fail(
      'resource-exhausted',
      'รูปภาพมีขนาดใหญ่เกิน 7 MB'
    );
  }

  return base64;
}

function decodeImageBase64(base64) {
  const buffer = Buffer.from(base64, 'base64');

  if (
    buffer.length === 0 ||
    buffer.length > CONFIG.IMAGE.MAX_BYTES
  ) {
    fail(
      'invalid-argument',
      'ขนาดรูปภาพไม่ถูกต้อง'
    );
  }

  return buffer;
}

function validateImageSignature(buffer, mimeType) {
  const isJpeg =
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff;

  const isPng =
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a;

  const isGif =
    buffer.length >= 6 &&
    buffer.toString('ascii', 0, 3) === 'GIF';

  const isWebp =
    buffer.length >= 12 &&
    buffer.toString('ascii', 0, 4) === 'RIFF' &&
    buffer.toString('ascii', 8, 12) === 'WEBP';

  const valid =
    (mimeType === 'image/jpeg' && isJpeg) ||
    (mimeType === 'image/png' && isPng) ||
    (mimeType === 'image/gif' && isGif) ||
    (mimeType === 'image/webp' && isWebp);

  if (!valid) {
    fail(
      'invalid-argument',
      'ชนิดไฟล์ไม่ตรงกับข้อมูลรูปภาพจริง'
    );
  }
}

function validateUsername(username) {
  const normalized = normalizeUsername(username);

  if (!/^[a-z0-9._-]{3,64}$/.test(normalized)) {
    fail(
      'invalid-argument',
      'ชื่อผู้ใช้ต้องมีความยาว 3–64 ตัวอักษร'
    );
  }

  return normalized;
}

function validatePassword(password) {
  if (
    typeof password !== 'string' ||
    password.length < 8 ||
    password.length > 128
  ) {
    fail(
      'invalid-argument',
      'รหัสผ่านต้องมีความยาว 8–128 ตัวอักษร'
    );
  }

  return password;
}

/* ============================================================================
 * IMGBB
 * ========================================================================== */

async function uploadBufferToImgBB(
  buffer,
  mimeType,
  filename
) {
  const apiKey = cleanString(
    IMGBB_API_KEY.value(),
    500
  );

  if (!apiKey) {
    fail(
      'failed-precondition',
      'ยังไม่ได้กำหนด IMGBB_API_KEY ใน Secret Manager'
    );
  }

  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, CONFIG.IMAGE.IMGBB_TIMEOUT_MS);

  try {
    const form = new FormData();

    form.append(
      'image',
      buffer.toString('base64')
    );

    form.append(
      'name',
      cleanString(filename, 200) || 'actigallery-image'
    );

    const endpoint = new URL(
      'https://api.imgbb.com/1/upload'
    );

    endpoint.searchParams.set('key', apiKey);

    const response = await fetch(endpoint.toString(), {
      method: 'POST',
      body: form,
      signal: controller.signal
    });

    const responseText = await response.text();

    let result;

    try {
      result = JSON.parse(responseText);
    } catch {
      logger.error('ImgBB returned invalid JSON');

      fail(
        'internal',
        'บริการจัดเก็บรูปภาพตอบกลับไม่ถูกต้อง'
      );
    }

    if (!response.ok || !result.success || !result.data) {
      logger.error('ImgBB upload failed', {
        status: response.status,
        error: result.error
          ? {
              code: result.error.code,
              message: result.error.message
            }
          : null
      });

      fail(
        'unavailable',
        'อัปโหลดรูปภาพไปยัง ImgBB ไม่สำเร็จ'
      );
    }

    const imageUrl = cleanString(
      result.data.url,
      2000
    );

    const displayUrl = cleanString(
      result.data.display_url || result.data.url,
      2000
    );

    const deleteUrl = cleanString(
      result.data.delete_url,
      2000
    );

    if (
      !imageUrl.startsWith('https://') ||
      !displayUrl.startsWith('https://')
    ) {
      fail(
        'internal',
        'ImgBB ส่ง URL รูปภาพที่ไม่ถูกต้อง'
      );
    }

    return {
      url: imageUrl,
      displayUrl,
      deleteUrl: deleteUrl || null,
      mimeType,
      size: buffer.length,
      uploadedAt: serverTimestamp()
    };
  } catch (error) {
    if (error instanceof HttpsError) {
      throw error;
    }

    if (error && error.name === 'AbortError') {
      fail(
        'deadline-exceeded',
        'การอัปโหลดรูปภาพใช้เวลานานเกินไป กรุณาลองใหม่'
      );
    }

    logger.error('ImgBB upload exception', {
      message: error?.message || 'Unknown error'
    });

    fail(
      'unavailable',
      'ไม่สามารถเชื่อมต่อบริการจัดเก็บรูปภาพได้'
    );
  } finally {
    clearTimeout(timeout);
  }
}

/* ============================================================================
 * DASHBOARD INITIAL DATA
 * ========================================================================== */

async function listOrganizations(actor) {
  let query = getCollection(
    CONFIG.COLLECTIONS.ORGANIZATIONS
  );

  if (!isAdmin(actor)) {
    const organizationId = getOrganizationId(actor);

    if (!organizationId) {
      return [];
    }

    const snapshot = await query
      .doc(organizationId)
      .get();

    return snapshot.exists
      ? [serializeDocument(snapshot)]
      : [];
  }

  const snapshot = await query
    .orderBy('createdAt', 'desc')
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  return snapshot.docs.map(serializeDocument);
}

async function listCategories(actor) {
  let query = getCollection(
    CONFIG.COLLECTIONS.CATEGORIES
  );

  if (!isAdmin(actor)) {
    query = query.where(
      'organizationId',
      '==',
      getOrganizationId(actor)
    );
  }

  const snapshot = await query
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  return snapshot.docs.map(serializeDocument);
}

async function listUsers(actor) {
  if (!isAdmin(actor)) {
    return [];
  }

  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.USERS
  )
    .orderBy('createdAt', 'desc')
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  return snapshot.docs.map((doc) => {
    const data = serializeDocument(doc);

    delete data.password;
    delete data.passwordHash;
    delete data.resetToken;

    return data;
  });
}

async function listAlbums(actor) {
  let query = getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  );

  if (!isAdmin(actor)) {
    query = query.where(
      'organizationId',
      '==',
      getOrganizationId(actor)
    );
  }

  const snapshot = await query
    .orderBy('createdAt', 'desc')
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  return snapshot.docs.map(serializeDocument);
}

async function listPhotosForAlbums(albums) {
  const albumIds = albums
    .map((album) => album.id)
    .filter(Boolean);

  if (albumIds.length === 0) {
    return [];
  }

  const chunks = chunkArray(albumIds, 30);
  const output = [];

  for (const chunk of chunks) {
    const snapshot = await getCollection(
      CONFIG.COLLECTIONS.PHOTOS
    )
      .where('albumId', 'in', chunk)
      .where('status', '==', CONFIG.PHOTO_STATUS.READY)
      .limit(CONFIG.MAX_LIST_LIMIT)
      .get();

    output.push(
      ...snapshot.docs.map(serializeDocument)
    );
  }

  output.sort((a, b) => {
    return safeInteger(a.order) - safeInteger(b.order);
  });

  return output;
}

async function getDashboardStats(
  actor,
  albums,
  photos,
  organizations,
  users
) {
  const publishedAlbums = albums.filter(
    (album) => album.status === CONFIG.ALBUM_STATUS.PUBLISHED
  );

  const activePhotos = photos.filter(
    (photo) => photo.status === CONFIG.PHOTO_STATUS.READY
  );

  return {
    photoCount: activePhotos.length,
    albumCount: albums.length,
    publishedAlbumCount: publishedAlbums.length,
    organizationCount: isAdmin(actor)
      ? organizations.length
      : organizations.length,
    userCount: isAdmin(actor)
      ? users.length
      : 1
  };
}

async function handleDashboardInit(request) {
  const actor = await requireAlbumManagerOrAdmin(request);

  const [
    organizations,
    categories,
    albums,
    users
  ] = await Promise.all([
    listOrganizations(actor),
    listCategories(actor),
    listAlbums(actor),
    listUsers(actor)
  ]);

  const photos = await listPhotosForAlbums(albums);

  const stats = await getDashboardStats(
    actor,
    albums,
    photos,
    organizations,
    users
  );

  return {
    success: true,
    appName: CONFIG.APP_NAME,
    version: CONFIG.VERSION,

    profile: serializeProfile(actor.profile),

    permissions: {
      isAdmin: isAdmin(actor),
      canManageUsers: isAdmin(actor),
      canManageOrganizations: isAdmin(actor),
      canManageCategories: true,
      canManageAlbums: true,
      canManagePhotos: true
    },

    stats,
    users,
    organizations,
    categories,
    albums,
    photos
  };
}

/* ============================================================================
 * ALBUMS
 * ========================================================================== */

async function handleSaveAlbum(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const title = requiredString(
    data.title,
    'ชื่ออัลบั้ม',
    300
  );

  const description = optionalString(
    data.description,
    5000
  );

  const organizationId = isAdmin(actor)
    ? requiredString(data.organizationId, 'องค์กร', 200)
    : getOrganizationId(actor);

  if (!organizationId) {
    fail(
      'failed-precondition',
      'กรุณากำหนดองค์กรให้บัญชีผู้ใช้ก่อน'
    );
  }

  assertOrganizationScope(actor, organizationId);

  await getOrganization(organizationId);

  const categoryId = optionalString(
    data.categoryId,
    200
  );

  if (categoryId) {
    const categorySnapshot = await getCollection(
      CONFIG.COLLECTIONS.CATEGORIES
    )
      .doc(categoryId)
      .get();

    if (!categorySnapshot.exists) {
      fail('not-found', 'ไม่พบหมวดหมู่ที่เลือก');
    }

    const category = categorySnapshot.data();

    if (
      category.organizationId &&
      category.organizationId !== organizationId
    ) {
      fail(
        'permission-denied',
        'หมวดหมู่ดังกล่าวไม่ได้อยู่ในองค์กรที่เลือก'
      );
    }
  }

  const albumId = cleanString(data.id, 200);

  const albumRef = albumId
    ? getCollection(CONFIG.COLLECTIONS.ALBUMS).doc(
        validateDocumentId(albumId, 'รหัสอัลบั้ม')
      )
    : getCollection(CONFIG.COLLECTIONS.ALBUMS).doc();

  let existingData = null;

  if (albumId) {
    const existingSnapshot = await albumRef.get();

    if (!existingSnapshot.exists) {
      fail('not-found', 'ไม่พบอัลบั้มที่ต้องการแก้ไข');
    }

    existingData = existingSnapshot.data();

    assertOrganizationScope(
      actor,
      existingData.organizationId
    );
  }

  const requestedStatus = cleanString(data.status, 50);

  let status = existingData
    ? existingData.status
    : CONFIG.ALBUM_STATUS.DRAFT;

  if (
    requestedStatus &&
    Object.values(CONFIG.ALBUM_STATUS).includes(requestedStatus)
  ) {
    status = requestedStatus;
  }

  const album = {
    title,
    description,
    organizationId,
    categoryId: categoryId || null,

    coverUrl: optionalString(data.coverUrl, 2000) ||
      (existingData ? existingData.coverUrl || null : null),

    status,

    createdBy: existingData
      ? existingData.createdBy || actor.uid
      : actor.uid,

    updatedBy: actor.uid,
    updatedAt: serverTimestamp(),

    createdAt: existingData
      ? existingData.createdAt || serverTimestamp()
      : serverTimestamp()
  };

  await albumRef.set(album, { merge: true });

  return {
    success: true,
    id: albumRef.id,
    album: {
      id: albumRef.id,
      ...album
    }
  };
}

async function handlePublishAlbum(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const albumId = validateDocumentId(
    data.albumId || data.id,
    'รหัสอัลบั้ม'
  );

  const album = await requireAlbumAccess(actor, albumId);

  const photosSnapshot = await getCollection(
    CONFIG.COLLECTIONS.PHOTOS
  )
    .where('albumId', '==', albumId)
    .where('status', '==', CONFIG.PHOTO_STATUS.READY)
    .limit(1)
    .get();

  if (photosSnapshot.empty) {
    fail(
      'failed-precondition',
      'อัลบั้มนี้ยังไม่มีรูปภาพที่อัปโหลดสำเร็จ'
    );
  }

  const coverUrl = optionalString(
    data.coverUrl,
    2000
  ) || album.coverUrl || null;

  await getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  ).doc(albumId).set({
    status: CONFIG.ALBUM_STATUS.PUBLISHED,
    publishedAt: serverTimestamp(),
    publishedBy: actor.uid,
    coverUrl,
    updatedAt: serverTimestamp(),
    updatedBy: actor.uid
  }, { merge: true });

  return {
    success: true,
    albumId,
    status: CONFIG.ALBUM_STATUS.PUBLISHED,
    message: 'เผยแพร่อัลบั้มเรียบร้อยแล้ว'
  };
}

async function handleDeleteAlbum(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const albumId = validateDocumentId(
    data.albumId || data.id,
    'รหัสอัลบั้ม'
  );

  await requireAlbumAccess(actor, albumId);

  const photosSnapshot = await getCollection(
    CONFIG.COLLECTIONS.PHOTOS
  )
    .where('albumId', '==', albumId)
    .get();

  const batchItems = [
    ...photosSnapshot.docs.map((doc) => ({
      ref: doc.ref,
      data: null
    })),
    {
      ref: getCollection(CONFIG.COLLECTIONS.ALBUMS).doc(albumId),
      data: null
    }
  ];

  for (const chunk of chunkArray(
    batchItems,
    CONFIG.MAX_BATCH_OPERATIONS
  )) {
    const batch = db.batch();

    for (const item of chunk) {
      batch.delete(item.ref);
    }

    await batch.commit();
  }

  return {
    success: true,
    albumId,
    deletedPhotos: photosSnapshot.size,
    message: 'ลบอัลบั้มเรียบร้อยแล้ว'
  };
}

async function handleListAlbumPhotos(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const albumId = validateDocumentId(
    data.albumId || data.id,
    'รหัสอัลบั้ม'
  );

  await requireAlbumAccess(actor, albumId);

  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.PHOTOS
  )
    .where('albumId', '==', albumId)
    .where('status', '==', CONFIG.PHOTO_STATUS.READY)
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  const photos = snapshot.docs.map(serializeDocument);

  photos.sort((a, b) => {
    return safeInteger(a.order) - safeInteger(b.order);
  });

  return {
    success: true,
    albumId,
    photos
  };
}

/* ============================================================================
 * PHOTO RECORDS
 * ========================================================================== */

async function handleSaveAlbumPhotos(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const albumId = validateDocumentId(
    data.albumId,
    'รหัสอัลบั้ม'
  );

  await requireAlbumAccess(actor, albumId);

  if (!Array.isArray(data.photos)) {
    fail('invalid-argument', 'รายการรูปภาพไม่ถูกต้อง');
  }

  if (data.photos.length > CONFIG.MAX_PHOTOS_PER_REQUEST) {
    fail(
      'invalid-argument',
      `บันทึกรูปได้ไม่เกิน ${CONFIG.MAX_PHOTOS_PER_REQUEST} รูปต่อคำขอ`
    );
  }

  const albumRef = getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  ).doc(albumId);

  const batch = db.batch();
  let validPhotoCount = 0;
  let firstPhotoUrl = null;

  for (let index = 0; index < data.photos.length; index++) {
    const photo = data.photos[index];

    if (!isPlainObject(photo)) {
      fail('invalid-argument', 'ข้อมูลรูปภาพไม่ถูกต้อง');
    }

    const url = requiredString(
      photo.url,
      'URL รูปภาพ',
      2000
    );

    if (!url.startsWith('https://')) {
      fail(
        'invalid-argument',
        'URL รูปภาพต้องเป็น HTTPS'
      );
    }

    const photoId = cleanString(photo.id, 200) || makeId();

    const ref = getCollection(
      CONFIG.COLLECTIONS.PHOTOS
    ).doc(validateDocumentId(photoId, 'รหัสรูปภาพ'));

    const record = {
      albumId,
      organizationId: cleanString(
        photo.organizationId,
        200
      ) || getOrganizationId(actor),

      url,
      displayUrl: cleanString(
        photo.displayUrl,
        2000
      ) || url,

      thumbnailUrl: cleanString(
        photo.thumbnailUrl,
        2000
      ) || url,

      filename: cleanString(
        photo.filename,
        300
      ) || `photo-${index + 1}`,

      caption: optionalString(photo.caption, 1000),

      order: Number.isFinite(Number(photo.order))
        ? Math.max(0, Math.trunc(Number(photo.order)))
        : index,

      status: CONFIG.PHOTO_STATUS.READY,

      createdBy: actor.uid,
      updatedBy: actor.uid,
      updatedAt: serverTimestamp(),
      createdAt: serverTimestamp()
    };

    assertOrganizationScope(
      actor,
      record.organizationId
    );

    batch.set(ref, record, { merge: true });

    if (!firstPhotoUrl) {
      firstPhotoUrl = record.displayUrl;
    }

    validPhotoCount++;
  }

  if (validPhotoCount > 0) {
    batch.set(albumRef, {
      coverUrl: firstPhotoUrl,
      photoCount: FieldValue.increment(validPhotoCount),
      updatedAt: serverTimestamp(),
      updatedBy: actor.uid
    }, { merge: true });
  }

  await batch.commit();

  return {
    success: true,
    albumId,
    savedCount: validPhotoCount,
    message: 'บันทึกรายการรูปภาพเรียบร้อยแล้ว'
  };
}

async function handleDeletePhotos(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const photoIds = assertStringArray(
    data.photoIds || data.ids,
    'รายการรูปภาพ',
    CONFIG.MAX_BATCH_OPERATIONS
  );

  if (photoIds.length === 0) {
    fail('invalid-argument', 'กรุณาเลือกรูปภาพที่ต้องการลบ');
  }

  const photoRefs = photoIds.map((id) =>
    getCollection(CONFIG.COLLECTIONS.PHOTOS)
      .doc(validateDocumentId(id, 'รหัสรูปภาพ'))
  );

  const snapshots = await db.getAll(...photoRefs);

  const batch = db.batch();
  const affectedAlbumIds = new Set();
  let deletedCount = 0;

  for (const snapshot of snapshots) {
    if (!snapshot.exists) {
      continue;
    }

    const photo = snapshot.data();

    assertOrganizationScope(
      actor,
      photo.organizationId
    );

    affectedAlbumIds.add(photo.albumId);
    batch.delete(snapshot.ref);
    deletedCount++;
  }

  await batch.commit();

  for (const albumId of affectedAlbumIds) {
    const albumRef = getCollection(
      CONFIG.COLLECTIONS.ALBUMS
    ).doc(albumId);

    await db.runTransaction(async (transaction) => {
      const albumSnapshot = await transaction.get(albumRef);

      if (!albumSnapshot.exists) {
        return;
      }

      const album = albumSnapshot.data();

      const nextCount = Math.max(
        0,
        safeInteger(album.photoCount) - deletedCount
      );

      transaction.set(albumRef, {
        photoCount: nextCount,
        updatedAt: serverTimestamp(),
        updatedBy: actor.uid
      }, { merge: true });
    });
  }

  return {
    success: true,
    deletedCount,
    message: 'ลบรูปภาพที่เลือกเรียบร้อยแล้ว'
  };
}

async function handleReorderPhotos(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const albumId = validateDocumentId(
    data.albumId,
    'รหัสอัลบั้ม'
  );

  await requireAlbumAccess(actor, albumId);

  const photoIds = assertStringArray(
    data.photoIds || data.orderedIds,
    'ลำดับรูปภาพ',
    CONFIG.MAX_BATCH_OPERATIONS
  );

  if (new Set(photoIds).size !== photoIds.length) {
    fail(
      'invalid-argument',
      'พบรหัสรูปภาพซ้ำในรายการเรียงลำดับ'
    );
  }

  const refs = photoIds.map((id) =>
    getCollection(CONFIG.COLLECTIONS.PHOTOS)
      .doc(validateDocumentId(id, 'รหัสรูปภาพ'))
  );

  const snapshots = await db.getAll(...refs);

  for (let index = 0; index < snapshots.length; index++) {
    const snapshot = snapshots[index];

    if (!snapshot.exists) {
      fail(
        'not-found',
        `ไม่พบรูปภาพรหัส ${photoIds[index]}`
      );
    }

    const photo = snapshot.data();

    if (photo.albumId !== albumId) {
      fail(
        'permission-denied',
        'พบรูปภาพที่ไม่ได้อยู่ในอัลบั้มนี้'
      );
    }

    assertOrganizationScope(
      actor,
      photo.organizationId
    );
  }

  for (const group of chunkArray(
    snapshots,
    CONFIG.MAX_BATCH_OPERATIONS
  )) {
    const batch = db.batch();

    for (const snapshot of group) {
      const index = snapshots.indexOf(snapshot);

      batch.set(snapshot.ref, {
        order: index,
        updatedAt: serverTimestamp(),
        updatedBy: actor.uid
      }, { merge: true });
    }

    await batch.commit();
  }

  return {
    success: true,
    albumId,
    count: photoIds.length,
    message: 'บันทึกลำดับรูปภาพเรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * IMAGE UPLOAD ENDPOINT
 * ========================================================================== */

async function handleUploadImage(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const purpose = cleanString(
    data.purpose || data.type,
    50
  ).toLowerCase();

  const isLogo =
    purpose === 'logo' ||
    purpose === 'organization_logo' ||
    purpose === 'organization-logo';

  if (isLogo && !isAdmin(actor)) {
    fail(
      'permission-denied',
      'เฉพาะผู้ดูแลระบบเท่านั้นที่อัปโหลดโลโก้องค์กรได้'
    );
  }

  let organizationId = cleanString(
    data.organizationId,
    200
  );

  let albumId = cleanString(data.albumId, 200);

  if (isLogo) {
    organizationId = requiredString(
      organizationId,
      'รหัสองค์กร',
      200
    );

    assertOrganizationScope(actor, organizationId);

    await getOrganization(organizationId);
  } else {
    albumId = requiredString(
      albumId,
      'รหัสอัลบั้ม',
      200
    );

    const album = await requireAlbumAccess(
      actor,
      albumId
    );

    organizationId = album.organizationId;
  }

  const mimeType = validateImageMimeType(
    data.mimeType || data.contentType
  );

  const base64 = validateImageBase64(
    data.base64 || data.imageBase64 || data.image
  );

  const buffer = decodeImageBase64(base64);

  validateImageSignature(buffer, mimeType);

  const filename = cleanString(
    data.filename || data.name,
    200
  ) || `actigallery-${Date.now()}`;

  const uploaded = await uploadBufferToImgBB(
    buffer,
    mimeType,
    filename
  );

  const photoId = makeId();

  if (isLogo) {
    const organizationRef = getCollection(
      CONFIG.COLLECTIONS.ORGANIZATIONS
    ).doc(organizationId);

    await organizationRef.set({
      logoUrl: uploaded.displayUrl,
      logoImageUrl: uploaded.url,
      updatedAt: serverTimestamp(),
      updatedBy: actor.uid
    }, { merge: true });

    return {
      success: true,
      purpose: 'logo',
      organizationId,
      url: uploaded.url,
      displayUrl: uploaded.displayUrl,
      message: 'อัปโหลดโลโก้องค์กรเรียบร้อยแล้ว'
    };
  }

  const photoRecord = {
    albumId,
    organizationId,
    url: uploaded.url,
    displayUrl: uploaded.displayUrl,
    thumbnailUrl: uploaded.displayUrl,
    filename,
    mimeType: uploaded.mimeType,
    size: uploaded.size,
    order: Number.isFinite(Number(data.order))
      ? Math.max(0, Math.trunc(Number(data.order)))
      : nowMilliseconds(),

    status: CONFIG.PHOTO_STATUS.READY,

    createdBy: actor.uid,
    updatedBy: actor.uid,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  await getCollection(
    CONFIG.COLLECTIONS.PHOTOS
  ).doc(photoId).set(photoRecord);

  await getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  ).doc(albumId).set({
    photoCount: FieldValue.increment(1),
    updatedAt: serverTimestamp(),
    updatedBy: actor.uid
  }, { merge: true });

  return {
    success: true,
    purpose: 'photo',
    photo: {
      id: photoId,
      ...serializeForClient(photoRecord)
    },
    url: uploaded.url,
    displayUrl: uploaded.displayUrl,
    message: 'อัปโหลดรูปภาพเรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * ORGANIZATIONS
 * ========================================================================== */

async function handleSaveOrganization(request) {
  const actor = await requireAdmin(request);
  const data = getRequestData(request);

  const name = requiredString(
    data.name || data.organizationName,
    'ชื่อองค์กร',
    300
  );

  const id = cleanString(
    data.id || data.organizationId,
    200
  );

  const ref = id
    ? getCollection(CONFIG.COLLECTIONS.ORGANIZATIONS)
        .doc(validateDocumentId(id, 'รหัสองค์กร'))
    : getCollection(CONFIG.COLLECTIONS.ORGANIZATIONS).doc();

  let existing = null;

  if (id) {
    const snapshot = await ref.get();

    if (!snapshot.exists) {
      fail(
        'not-found',
        'ไม่พบองค์กรที่ต้องการแก้ไข'
      );
    }

    existing = snapshot.data();
  }

  const organization = {
    name,
    description: optionalString(data.description, 2000),

    logoUrl: optionalString(
      data.logoUrl,
      2000
    ) || (existing ? existing.logoUrl || null : null),

    logoImageUrl: optionalString(
      data.logoImageUrl,
      2000
    ) || (existing ? existing.logoImageUrl || null : null),

    status: cleanString(data.status, 50) ||
      (existing ? existing.status : 'active'),

    createdBy: existing
      ? existing.createdBy || actor.uid
      : actor.uid,

    updatedBy: actor.uid,
    updatedAt: serverTimestamp(),

    createdAt: existing
      ? existing.createdAt || serverTimestamp()
      : serverTimestamp()
  };

  await ref.set(organization, { merge: true });

  return {
    success: true,
    id: ref.id,
    organization: {
      id: ref.id,
      ...organization
    },
    message: 'บันทึกข้อมูลองค์กรเรียบร้อยแล้ว'
  };
}

async function handleDeleteOrganization(request) {
  const actor = await requireAdmin(request);
  const data = getRequestData(request);

  const organizationId = validateDocumentId(
    data.organizationId || data.id,
    'รหัสองค์กร'
  );

  const organizationRef = getCollection(
    CONFIG.COLLECTIONS.ORGANIZATIONS
  ).doc(organizationId);

  const organizationSnapshot = await organizationRef.get();

  if (!organizationSnapshot.exists) {
    fail('not-found', 'ไม่พบองค์กรที่ต้องการลบ');
  }

  const [
    usersSnapshot,
    albumsSnapshot,
    categoriesSnapshot
  ] = await Promise.all([
    getCollection(CONFIG.COLLECTIONS.USERS)
      .where('organizationId', '==', organizationId)
      .limit(1)
      .get(),

    getCollection(CONFIG.COLLECTIONS.ALBUMS)
      .where('organizationId', '==', organizationId)
      .limit(1)
      .get(),

    getCollection(CONFIG.COLLECTIONS.CATEGORIES)
      .where('organizationId', '==', organizationId)
      .limit(1)
      .get()
  ]);

  if (
    !usersSnapshot.empty ||
    !albumsSnapshot.empty ||
    !categoriesSnapshot.empty
  ) {
    fail(
      'failed-precondition',
      'ไม่สามารถลบองค์กรได้ เนื่องจากยังมีผู้ใช้ อัลบั้ม หรือหมวดหมู่ที่เกี่ยวข้อง'
    );
  }

  await organizationRef.delete();

  return {
    success: true,
    organizationId,
    message: 'ลบองค์กรเรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * CATEGORIES
 * ========================================================================== */

async function handleSaveCategory(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const name = requiredString(
    data.name || data.categoryName,
    'ชื่อหมวดหมู่',
    200
  );

  const organizationId = isAdmin(actor)
    ? requiredString(data.organizationId, 'องค์กร', 200)
    : getOrganizationId(actor);

  assertOrganizationScope(actor, organizationId);

  await getOrganization(organizationId);

  const id = cleanString(
    data.id || data.categoryId,
    200
  );

  const ref = id
    ? getCollection(CONFIG.COLLECTIONS.CATEGORIES)
        .doc(validateDocumentId(id, 'รหัสหมวดหมู่'))
    : getCollection(CONFIG.COLLECTIONS.CATEGORIES).doc();

  let existing = null;

  if (id) {
    const snapshot = await ref.get();

    if (!snapshot.exists) {
      fail(
        'not-found',
        'ไม่พบหมวดหมู่ที่ต้องการแก้ไข'
      );
    }

    existing = snapshot.data();

    assertOrganizationScope(
      actor,
      existing.organizationId
    );
  }

  const category = {
    name,
    description: optionalString(data.description, 1000),
    organizationId,

    createdBy: existing
      ? existing.createdBy || actor.uid
      : actor.uid,

    updatedBy: actor.uid,
    updatedAt: serverTimestamp(),

    createdAt: existing
      ? existing.createdAt || serverTimestamp()
      : serverTimestamp()
  };

  await ref.set(category, { merge: true });

  return {
    success: true,
    id: ref.id,
    category: {
      id: ref.id,
      ...category
    },
    message: 'บันทึกหมวดหมู่เรียบร้อยแล้ว'
  };
}

async function handleDeleteCategory(request) {
  const actor = await requireAlbumManagerOrAdmin(request);
  const data = getRequestData(request);

  const categoryId = validateDocumentId(
    data.categoryId || data.id,
    'รหัสหมวดหมู่'
  );

  const categoryRef = getCollection(
    CONFIG.COLLECTIONS.CATEGORIES
  ).doc(categoryId);

  const categorySnapshot = await categoryRef.get();

  if (!categorySnapshot.exists) {
    fail('not-found', 'ไม่พบหมวดหมู่ที่ต้องการลบ');
  }

  const category = categorySnapshot.data();

  assertOrganizationScope(
    actor,
    category.organizationId
  );

  const albumsSnapshot = await getCollection(
    CONFIG.COLLECTIONS.ALBUMS
  )
    .where('categoryId', '==', categoryId)
    .limit(1)
    .get();

  if (!albumsSnapshot.empty) {
    fail(
      'failed-precondition',
      'ไม่สามารถลบหมวดหมู่นี้ได้ เพราะยังมีอัลบั้มใช้งานอยู่'
    );
  }

  await categoryRef.delete();

  return {
    success: true,
    categoryId,
    message: 'ลบหมวดหมู่เรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * USERS
 * ========================================================================== */

async function generateNextInitialPassword() {
  const snapshot = await getCollection(
    CONFIG.COLLECTIONS.USERS
  )
    .orderBy('createdAt', 'desc')
    .limit(CONFIG.MAX_LIST_LIMIT)
    .get();

  let maxNumber = 0;

  for (const doc of snapshot.docs) {
    const username = cleanString(
      doc.data().username,
      100
    );

    const match = username.match(/^GF(\d{6})$/i);

    if (match) {
      maxNumber = Math.max(
        maxNumber,
        Number(match[1])
      );
    }
  }

  return makeInitialPassword(maxNumber + 1);
}

async function handleCreateUser(request) {
  const actor = await requireAdmin(request);
  const data = getRequestData(request);

  const fullName = requiredString(
    data.fullName || data.name,
    'ชื่อ-นามสกุล',
    300
  );

  const username = validateUsername(data.username);

  const email = usernameToEmail(username);

  const role = normalizeRole(
    data.role || CONFIG.ROLES.ALBUM_MANAGER
  );

  const organizationId = requiredString(
    data.organizationId,
    'องค์กร',
    200
  );

  await getOrganization(organizationId);

  let password = cleanString(data.password, 128);

  if (!password) {
    password = await generateNextInitialPassword();
  } else {
    password = validatePassword(password);
  }

  const existingProfile = await getCollection(
    CONFIG.COLLECTIONS.USERS
  )
    .where('username', '==', username)
    .limit(1)
    .get();

  if (!existingProfile.empty) {
    fail(
      'already-exists',
      'ชื่อผู้ใช้นี้ถูกใช้แล้ว'
    );
  }

  let userRecord;

  try {
    userRecord = await auth.createUser({
      email,
      password,
      displayName: fullName,
      disabled: false
    });
  } catch (error) {
    logger.error('Firebase Auth createUser failed', {
      code: error?.code || null,
      message: error?.message || null
    });

    if (
      error.code === 'auth/email-already-exists'
    ) {
      fail(
        'already-exists',
        'ชื่อผู้ใช้นี้ถูกใช้แล้ว'
      );
    }

    if (
      error.code === 'auth/invalid-password'
    ) {
      fail(
        'invalid-argument',
        'รหัสผ่านไม่เป็นไปตามข้อกำหนดของ Firebase'
      );
    }

    fail(
      'internal',
      'สร้างบัญชีผู้ใช้ไม่สำเร็จ'
    );
  }

  const profile = {
    uid: userRecord.uid,
    fullName,
    name: fullName,
    username,
    email,
    role,
    organizationId,
    status: CONFIG.USER_STATUS.ACTIVE,
    mustChangePassword: true,

    createdBy: actor.uid,
    updatedBy: actor.uid,

    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  try {
    await getCollection(
      CONFIG.COLLECTIONS.USERS
    )
      .doc(userRecord.uid)
      .set(profile);
  } catch (error) {
    try {
      await auth.deleteUser(userRecord.uid);
    } catch (rollbackError) {
      logger.error(
        'Could not roll back Auth account after Firestore failure',
        {
          uid: userRecord.uid,
          message: rollbackError?.message || null
        }
      );
    }

    logger.error('Failed to save user profile', {
      uid: userRecord.uid,
      message: error?.message || null
    });

    fail(
      'internal',
      'สร้างข้อมูลผู้ใช้ไม่สำเร็จ'
    );
  }

  return {
    success: true,
    user: {
      uid: userRecord.uid,
      fullName,
      username,
      email,
      role,
      organizationId,
      status: CONFIG.USER_STATUS.ACTIVE
    },
    initialPassword: password,
    mustChangePassword: true,
    message: 'สร้างบัญชีผู้ใช้เรียบร้อยแล้ว'
  };
}

async function handleUpdateUser(request) {
  const actor = await requireAdmin(request);
  const data = getRequestData(request);

  const uid = requiredString(
    data.uid || data.userId,
    'รหัสผู้ใช้',
    200
  );

  const userRef = getCollection(
    CONFIG.COLLECTIONS.USERS
  ).doc(uid);

  const userSnapshot = await userRef.get();

  if (!userSnapshot.exists) {
    fail('not-found', 'ไม่พบผู้ใช้ที่ต้องการแก้ไข');
  }

  const existing = userSnapshot.data();

  const updates = {
    updatedBy: actor.uid,
    updatedAt: serverTimestamp()
  };

  if (data.fullName !== undefined || data.name !== undefined) {
    const fullName = requiredString(
      data.fullName || data.name,
      'ชื่อ-นามสกุล',
      300
    );

    updates.fullName = fullName;
    updates.name = fullName;

    await auth.updateUser(uid, {
      displayName: fullName
    });
  }

  if (data.organizationId !== undefined) {
    const organizationId = requiredString(
      data.organizationId,
      'องค์กร',
      200
    );

    await getOrganization(organizationId);

    updates.organizationId = organizationId;
  }

  if (data.role !== undefined) {
    updates.role = normalizeRole(data.role);
  }

  if (data.status !== undefined) {
    const status = normalizeStatus(
      data.status,
      [
        CONFIG.USER_STATUS.ACTIVE,
        CONFIG.USER_STATUS.DISABLED
      ],
      'สถานะผู้ใช้'
    );

    updates.status = status;

    await auth.updateUser(uid, {
      disabled: status === CONFIG.USER_STATUS.DISABLED
    });
  }

  if (data.password !== undefined && data.password !== '') {
    const password = validatePassword(data.password);

    await auth.updateUser(uid, { password });

    updates.mustChangePassword = true;
  }

  if (
    data.username !== undefined &&
    normalizeUsername(data.username) !== existing.username
  ) {
    fail(
      'failed-precondition',
      'การเปลี่ยนชื่อผู้ใช้หลังสร้างบัญชียังไม่รองรับ'
    );
  }

  await userRef.set(updates, { merge: true });

  const updatedSnapshot = await userRef.get();

  return {
    success: true,
    user: serializeProfile({
      uid,
      ...updatedSnapshot.data()
    }),
    message: 'แก้ไขข้อมูลผู้ใช้เรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * BOOTSTRAP ADMIN
 *
 * This endpoint creates the first administrator.
 * It requires BOOTSTRAP_KEY and refuses to run if an admin already exists.
 * After initialization, remove or rotate BOOTSTRAP_KEY.
 * ========================================================================== */

async function handleBootstrapAdmin(request) {
  const data = getRequestData(request);

  const suppliedKey = requiredString(
    data.bootstrapKey,
    'รหัสเริ่มต้นระบบ',
    500
  );

  const expectedKey = cleanString(
    BOOTSTRAP_KEY.value(),
    500
  );

  if (!expectedKey) {
    fail(
      'failed-precondition',
      'ยังไม่ได้กำหนด BOOTSTRAP_KEY ใน Secret Manager'
    );
  }

  const suppliedBuffer = Buffer.from(suppliedKey);
  const expectedBuffer = Buffer.from(expectedKey);

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    fail(
      'permission-denied',
      'รหัสเริ่มต้นระบบไม่ถูกต้อง'
    );
  }

  const existingAdminSnapshot = await getCollection(
    CONFIG.COLLECTIONS.USERS
  )
    .where('role', '==', CONFIG.ROLES.ADMIN)
    .limit(1)
    .get();

  if (!existingAdminSnapshot.empty) {
    fail(
      'already-exists',
      'ระบบมีผู้ดูแลระบบแล้ว ไม่สามารถเริ่มต้นซ้ำได้'
    );
  }

  const username = validateUsername(
    data.username || 'admin'
  );

  const fullName = requiredString(
    data.fullName || 'System Administrator',
    'ชื่อผู้ดูแลระบบ',
    300
  );

  const password = validatePassword(data.password);
  const email = usernameToEmail(username);

  let userRecord;

  try {
    userRecord = await auth.createUser({
      email,
      password,
      displayName: fullName,
      disabled: false
    });
  } catch (error) {
    logger.error('Bootstrap Auth creation failed', {
      code: error?.code || null,
      message: error?.message || null
    });

    if (error.code === 'auth/email-already-exists') {
      fail(
        'already-exists',
        'ชื่อผู้ใช้นี้มีอยู่แล้วใน Firebase Authentication'
      );
    }

    fail(
      'internal',
      'สร้างบัญชีผู้ดูแลระบบไม่สำเร็จ'
    );
  }

  const profile = {
    uid: userRecord.uid,
    fullName,
    name: fullName,
    username,
    email,
    role: CONFIG.ROLES.ADMIN,
    organizationId: null,
    status: CONFIG.USER_STATUS.ACTIVE,
    mustChangePassword: true,

    createdBy: 'bootstrap',
    updatedBy: 'bootstrap',

    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  try {
    await getCollection(
      CONFIG.COLLECTIONS.USERS
    )
      .doc(userRecord.uid)
      .set(profile);
  } catch (error) {
    try {
      await auth.deleteUser(userRecord.uid);
    } catch (rollbackError) {
      logger.error(
        'Bootstrap rollback failed',
        {
          uid: userRecord.uid,
          message: rollbackError?.message || null
        }
      );
    }

    fail(
      'internal',
      'บันทึกข้อมูลผู้ดูแลระบบไม่สำเร็จ'
    );
  }

  logger.warn('ActiGallery bootstrap admin created', {
    uid: userRecord.uid,
    username
  });

  return {
    success: true,
    uid: userRecord.uid,
    username,
    email,
    role: CONFIG.ROLES.ADMIN,
    message: 'สร้างบัญชีผู้ดูแลระบบเรียบร้อยแล้ว'
  };
}

/* ============================================================================
 * PUBLIC GALLERY
 *
 * Read-only public endpoint.
 * Only published albums and ready photos are returned.
 * ========================================================================== */

exports.publicGallery = onCall(
  {
    region: REGION,
    maxInstances: 10,
    enforceAppCheck: false
  },
  async (request) => {
    try {
      const data = isPlainObject(request.data)
        ? request.data
        : {};

      const organizationId = cleanString(
        data.organizationId,
        200
      );

      const categoryId = cleanString(
        data.categoryId,
        200
      );

      const albumId = cleanString(
        data.albumId,
        200
      );

      let albumQuery = getCollection(
        CONFIG.COLLECTIONS.ALBUMS
      ).where(
        'status',
        '==',
        CONFIG.ALBUM_STATUS.PUBLISHED
      );

      if (organizationId) {
        albumQuery = albumQuery.where(
          'organizationId',
          '==',
          organizationId
        );
      }

      if (categoryId) {
        albumQuery = albumQuery.where(
          'categoryId',
          '==',
          categoryId
        );
      }

      if (albumId) {
        albumQuery = albumQuery.where(
          admin.firestore.FieldPath.documentId(),
          '==',
          albumId
        );
      }

      const albumSnapshot = await albumQuery
        .limit(CONFIG.MAX_LIST_LIMIT)
        .get();

      const albums = albumSnapshot.docs.map(
        serializeDocument
      );

      const albumIds = albums.map((album) => album.id);

      let photos = [];

      for (const chunk of chunkArray(albumIds, 30)) {
        if (chunk.length === 0) {
          continue;
        }

        const photoSnapshot = await getCollection(
          CONFIG.COLLECTIONS.PHOTOS
        )
          .where('albumId', 'in', chunk)
          .where(
            'status',
            '==',
            CONFIG.PHOTO_STATUS.READY
          )
          .limit(CONFIG.MAX_LIST_LIMIT)
          .get();

        photos.push(
          ...photoSnapshot.docs.map(serializeDocument)
        );
      }

      photos.sort((a, b) => {
        return safeInteger(a.order) - safeInteger(b.order);
      });

      const organizationIds = [
        ...new Set(
          albums
            .map((album) => album.organizationId)
            .filter(Boolean)
        )
      ];

      const organizations = [];

      for (const id of organizationIds) {
        const snapshot = await getCollection(
          CONFIG.COLLECTIONS.ORGANIZATIONS
        )
          .doc(id)
          .get();

        if (snapshot.exists) {
          organizations.push(serializeDocument(snapshot));
        }
      }

      const categoryIds = [
        ...new Set(
          albums
            .map((album) => album.categoryId)
            .filter(Boolean)
        )
      ];

      const categories = [];

      for (const id of categoryIds) {
        const snapshot = await getCollection(
          CONFIG.COLLECTIONS.CATEGORIES
        )
          .doc(id)
          .get();

        if (snapshot.exists) {
          categories.push(serializeDocument(snapshot));
        }
      }

      return {
        success: true,
        albums,
        photos,
        organizations,
        categories
      };
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error('Public gallery request failed', {
        message: error?.message || null
      });

      fail(
        'internal',
        'ไม่สามารถโหลดข้อมูลแกลเลอรีได้'
      );
    }
  }
);

/* ============================================================================
 * MAIN DASHBOARD API
 * ========================================================================== */

exports.dashboardApi = onCall(
  {
    region: REGION,
    maxInstances: 10,
    enforceAppCheck: false
  },
  async (request) => {
    const data = getRequestData(request);
    const action = getAction(data);

    try {
      switch (action) {
        case 'dashboardInit':
          return await handleDashboardInit(request);

        case 'saveAlbum':
          return await handleSaveAlbum(request);

        case 'publishAlbum':
          return await handlePublishAlbum(request);

        case 'deleteAlbum':
          return await handleDeleteAlbum(request);

        case 'listAlbumPhotos':
          return await handleListAlbumPhotos(request);

        case 'saveAlbumPhotos':
          return await handleSaveAlbumPhotos(request);

        case 'deletePhotos':
          return await handleDeletePhotos(request);

        case 'reorderPhotos':
          return await handleReorderPhotos(request);

        case 'saveOrganization':
          return await handleSaveOrganization(request);

        case 'deleteOrganization':
          return await handleDeleteOrganization(request);

        case 'saveCategory':
          return await handleSaveCategory(request);

        case 'deleteCategory':
          return await handleDeleteCategory(request);

        case 'createUser':
          return await handleCreateUser(request);

        case 'updateUser':
          return await handleUpdateUser(request);

        default:
          fail(
            'invalid-argument',
            `ไม่รู้จักคำสั่ง: ${action}`
          );
      }
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error('dashboardApi request failed', {
        action,
        uid: request.auth?.uid || null,
        message: error?.message || null,
        code: error?.code || null
      });

      fail(
        'internal',
        'เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่อีกครั้ง'
      );
    }
  }
);

/* ============================================================================
 * IMAGE UPLOAD API
 * ========================================================================== */

exports.uploadImage = onCall(
  {
    region: REGION,
    secrets: [IMGBB_API_KEY],
    maxInstances: 10,
    timeoutSeconds: 120,
    memory: '512MiB',
    enforceAppCheck: false
  },
  async (request) => {
    try {
      return await handleUploadImage(request);
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error('uploadImage request failed', {
        uid: request.auth?.uid || null,
        message: error?.message || null,
        code: error?.code || null
      });

      fail(
        'internal',
        'อัปโหลดรูปภาพไม่สำเร็จ'
      );
    }
  }
);

/* ============================================================================
 * FIRST ADMIN BOOTSTRAP API
 * ========================================================================== */

exports.bootstrapAdmin = onCall(
  {
    region: REGION,
    secrets: [BOOTSTRAP_KEY],
    maxInstances: 1,
    enforceAppCheck: false
  },
  async (request) => {
    try {
      return await handleBootstrapAdmin(request);
    } catch (error) {
      if (error instanceof HttpsError) {
        throw error;
      }

      logger.error('bootstrapAdmin failed', {
        message: error?.message || null,
        code: error?.code || null
      });

      fail(
        'internal',
        'เริ่มต้นระบบไม่สำเร็จ'
      );
    }
  }
);

/* ============================================================================
 * PASSWORD CHANGE API
 *
 * Firebase Authentication does not expose the current user's password to
 * Cloud Functions. Password changes must use Firebase client SDK
 * reauthentication/updatePassword in the browser.
 *
 * This endpoint only clears the mustChangePassword flag after the client has
 * successfully changed the password and obtained a fresh ID token.
 *
 * Do not call this endpoint before the actual password change succeeds.
 * ========================================================================== */

exports.markPasswordChanged = onCall(
  {
    region: REGION,
    maxInstances: 10,
    enforceAppCheck: false
  },
  async (request) => {
    const actor = await requireSignedIn(request);

    await getCollection(
      CONFIG.COLLECTIONS.USERS
    )
      .doc(actor.uid)
      .set({
        mustChangePassword: false,
        updatedAt: serverTimestamp(),
        updatedBy: actor.uid
      }, { merge: true });

    return {
      success: true,
      message: 'อัปเดตสถานะรหัสผ่านเรียบร้อยแล้ว'
    };
  }
);

/* ============================================================================
 * HEALTH CHECK
 * ========================================================================== */

exports.healthCheck = onCall(
  {
    region: REGION,
    maxInstances: 5,
    enforceAppCheck: false
  },
  async () => {
    return {
      success: true,
      appName: CONFIG.APP_NAME,
      version: CONFIG.VERSION,
      region: CONFIG.REGION,
      timestamp: new Date().toISOString()
    };
  }
);
