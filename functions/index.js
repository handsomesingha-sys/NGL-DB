
"use strict";

/**
 * ================================================================
 * ActiGallery — Firebase Cloud Functions Backend
 * ================================================================
 *
 * Runtime:
 *   Node.js 20
 *
 * Firebase services:
 *   - Firebase Authentication
 *   - Cloud Firestore
 *   - Cloud Functions v2
 *   - ImgBB Image Hosting API
 *
 * Region:
 *   asia-southeast1
 *
 * Firestore collections:
 *   users
 *   organizations
 *   categories
 *   albums
 *   photos
 *   system
 *
 * Functions:
 *   dashboardApi
 *   uploadImage
 *   bootstrapAdmin
 *   markPasswordChanged
 *   publicGallery
 *   healthCheck
 *
 * Required Firebase Secrets:
 *   IMGBB_API_KEY
 *   BOOTSTRAP_KEY
 *
 * Username-to-email convention:
 *   username@users.actigallery.app
 *
 * Supported roles:
 *   admin
 *   album_manager
 *
 * Supported user statuses:
 *   active
 *   disabled
 *
 * IMPORTANT:
 *   1. Never deploy a Firebase Admin SDK service-account private key
 *      inside this file or inside the public GitHub repository.
 *   2. Set Firebase Secrets before deploying.
 *   3. Apply appropriate Firestore rules even though this backend
 *      performs authorization checks for callable requests.
 *   4. ImgBB API keys are server-side secrets, not browser settings.
 * ================================================================
 */

const {
    onCall,
    onRequest,
    HttpsError
} = require("firebase-functions/v2/https");

const {
    defineSecret
} = require("firebase-functions/params");

const logger = require("firebase-functions/logger");

const admin = require("firebase-admin");

const crypto = require("node:crypto");

const {
    getApps,
    initializeApp
} = require("firebase-admin/app");

const {
    getAuth
} = require("firebase-admin/auth");

const {
    getFirestore,
    FieldValue,
    Timestamp
} = require("firebase-admin/firestore");

/* ================================================================
 * 1. FIREBASE INITIALIZATION
 * ================================================================ */

if (getApps().length === 0) {
    initializeApp();
}

const db = getFirestore();
const firebaseAuth = getAuth();

const REGION = "asia-southeast1";

const COLLECTIONS = Object.freeze({
    USERS: "users",
    ORGANIZATIONS: "organizations",
    CATEGORIES: "categories",
    ALBUMS: "albums",
    PHOTOS: "photos",
    SYSTEM: "system"
});

const SECRET_IMGBB_API_KEY = defineSecret("IMGBB_API_KEY");
const SECRET_BOOTSTRAP_KEY = defineSecret("BOOTSTRAP_KEY");

const MAX_IMAGE_BYTES = 7 * 1024 * 1024;
const MAX_IMAGE_BASE64_LENGTH = Math.ceil(MAX_IMAGE_BYTES * 4 / 3) + 32;
const MAX_NAME_LENGTH = 180;
const MAX_DESCRIPTION_LENGTH = 5000;
const MAX_PHOTOS_PER_REQUEST = 100;
const MAX_BATCH_WRITES = 400;
const MAX_USERNAME_LENGTH = 50;
const MIN_USERNAME_LENGTH = 3;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

const ALLOWED_IMAGE_TYPES = Object.freeze([
    "image/jpeg",
    "image/png",
    "image/webp"
]);

const ALLOWED_ROLES = Object.freeze([
    "admin",
    "album_manager"
]);

const ALLOWED_USER_STATUSES = Object.freeze([
    "active",
    "disabled"
]);

const ALLOWED_ALBUM_STATUSES = Object.freeze([
    "draft",
    "published"
]);

const USER_EMAIL_DOMAIN = "@users.actigallery.app";

const DEFAULT_ADMIN_USERNAME = "sxaiq54";

const DEFAULT_ADMIN_DISPLAY_NAME = "ผู้ดูแลระบบ";

/* ================================================================
 * 2. GENERAL HELPERS
 * ================================================================ */

function nowTimestamp() {
    return Timestamp.now();
}

function serverTimestamp() {
    return FieldValue.serverTimestamp();
}

function cleanString(value, maximumLength = 1000) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .trim()
        .slice(0, maximumLength);
}

function requireString(value, fieldName, maximumLength = 1000) {
    const result = cleanString(value, maximumLength);

    if (!result) {
        throw new HttpsError(
            "invalid-argument",
            `กรุณาระบุ ${fieldName}`
        );
    }

    return result;
}

function normalizeUsername(value) {
    return cleanString(value, MAX_USERNAME_LENGTH).toLowerCase();
}

function validateUsername(value) {
    const username = normalizeUsername(value);

    if (
        username.length < MIN_USERNAME_LENGTH ||
        username.length > MAX_USERNAME_LENGTH
    ) {
        throw new HttpsError(
            "invalid-argument",
            `ชื่อผู้ใช้ต้องมี ${MIN_USERNAME_LENGTH}-${MAX_USERNAME_LENGTH} ตัวอักษร`
        );
    }

    if (!/^[a-z0-9._-]+$/.test(username)) {
        throw new HttpsError(
            "invalid-argument",
            "ชื่อผู้ใช้ใช้ได้เฉพาะ a-z, 0-9, จุด, ขีดกลาง และขีดล่าง"
        );
    }

    return username;
}

function usernameToEmail(username) {
    return `${validateUsername(username)}${USER_EMAIL_DOMAIN}`;
}

function normalizePassword(value) {
    return typeof value === "string" ? value : "";
}

function validatePassword(value, options = {}) {
    const password = normalizePassword(value);

    if (options.allowEmpty && !password) {
        return "";
    }

    if (
        password.length < MIN_PASSWORD_LENGTH ||
        password.length > MAX_PASSWORD_LENGTH
    ) {
        throw new HttpsError(
            "invalid-argument",
            `รหัสผ่านต้องมี ${MIN_PASSWORD_LENGTH}-${MAX_PASSWORD_LENGTH} ตัวอักษร`
        );
    }

    return password;
}

function validateRole(value) {
    const role = cleanString(value, 40).toLowerCase();

    if (!ALLOWED_ROLES.includes(role)) {
        throw new HttpsError(
            "invalid-argument",
            "สิทธิ์ผู้ใช้งานไม่ถูกต้อง"
        );
    }

    return role;
}

function validateUserStatus(value) {
    const status = cleanString(value || "active", 30).toLowerCase();

    if (!ALLOWED_USER_STATUSES.includes(status)) {
        throw new HttpsError(
            "invalid-argument",
            "สถานะผู้ใช้งานไม่ถูกต้อง"
        );
    }

    return status;
}

function validateAlbumStatus(value) {
    const status = cleanString(value || "draft", 30).toLowerCase();

    if (!ALLOWED_ALBUM_STATUSES.includes(status)) {
        throw new HttpsError(
            "invalid-argument",
            "สถานะอัลบั้มไม่ถูกต้อง"
        );
    }

    return status;
}

function requireUid(request) {
    const uid = request?.auth?.uid;

    if (!uid) {
        throw new HttpsError(
            "unauthenticated",
            "กรุณาเข้าสู่ระบบก่อนดำเนินการ"
        );
    }

    return uid;
}

function requireObject(value, fieldName = "ข้อมูล") {
    if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value)
    ) {
        throw new HttpsError(
            "invalid-argument",
            `${fieldName}ไม่ถูกต้อง`
        );
    }

    return value;
}

function normalizeId(value, fieldName = "รหัสข้อมูล") {
    const id = cleanString(value, 180);

    if (!id) {
        throw new HttpsError(
            "invalid-argument",
            `ไม่พบ${fieldName}`
        );
    }

    if (id.includes("/") || id === "." || id === "..") {
        throw new HttpsError(
            "invalid-argument",
            `${fieldName}ไม่ถูกต้อง`
        );
    }

    return id;
}

function normalizeHttpsUrl(value, fieldName = "URL") {
    const raw = cleanString(value, 4000);

    if (!raw) {
        return "";
    }

    let parsed;

    try {
        parsed = new URL(raw);
    } catch {
        throw new HttpsError(
            "invalid-argument",
            `${fieldName}ไม่ถูกต้อง`
        );
    }

    if (parsed.protocol !== "https:") {
        throw new HttpsError(
            "invalid-argument",
            `${fieldName}ต้องเป็น HTTPS`
        );
    }

    return parsed.toString();
}

function isAdminRole(profile) {
    return cleanString(profile?.role, 40).toLowerCase() === "admin";
}

function isAlbumManagerRole(profile) {
    return cleanString(profile?.role, 40).toLowerCase() === "album_manager";
}

function isActiveStatus(profile) {
    return cleanString(profile?.status || "active", 30).toLowerCase() === "active";
}

function toIsoDate(value) {
    if (!value) {
        return null;
    }

    if (typeof value.toDate === "function") {
        return value.toDate().toISOString();
    }

    if (value instanceof Date) {
        return value.toISOString();
    }

    if (typeof value === "number") {
        const date = new Date(value);

        return Number.isNaN(date.getTime())
            ? null
            : date.toISOString();
    }

    if (typeof value === "string") {
        const date = new Date(value);

        return Number.isNaN(date.getTime())
            ? null
            : date.toISOString();
    }

    if (typeof value === "object" && Number.isFinite(value.seconds)) {
        return new Date(value.seconds * 1000).toISOString();
    }

    return null;
}

function serializeDocument(documentSnapshot) {
    if (!documentSnapshot?.exists) {
        return null;
    }

    const data = documentSnapshot.data() || {};

    return {
        ...data,
        id: documentSnapshot.id,
        createdAt: toIsoDate(data.createdAt),
        updatedAt: toIsoDate(data.updatedAt),
        publishedAt: toIsoDate(data.publishedAt),
        passwordChangedAt: toIsoDate(data.passwordChangedAt)
    };
}

function serializeData(data, id) {
    if (!data) {
        return null;
    }

    return {
        ...data,
        ...(id ? { id } : {}),
        createdAt: toIsoDate(data.createdAt),
        updatedAt: toIsoDate(data.updatedAt),
        publishedAt: toIsoDate(data.publishedAt),
        passwordChangedAt: toIsoDate(data.passwordChangedAt)
    };
}

function getPublicError(error) {
    if (error instanceof HttpsError) {
        return error;
    }

    logger.error("Unhandled backend error", {
        message: error?.message || String(error),
        stack: error?.stack || ""
    });

    return new HttpsError(
        "internal",
        "เกิดข้อผิดพลาดภายในระบบ กรุณาลองใหม่"
    );
}

function generateInitialPassword(sequenceNumber) {
    const number = String(sequenceNumber).padStart(6, "0");

    return `GF${number}`;
}

function randomDocumentId() {
    return crypto.randomUUID();
}

function safeInteger(value, fallback = 0) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return fallback;
    }

    return Math.trunc(number);
}

function uniqueStrings(values) {
    if (!Array.isArray(values)) {
        return [];
    }

    return [...new Set(
        values
            .map(value => cleanString(value, 180))
            .filter(Boolean)
    )];
}

function chunkArray(values, chunkSize) {
    const chunks = [];

    for (let index = 0; index < values.length; index += chunkSize) {
        chunks.push(values.slice(index, index + chunkSize));
    }

    return chunks;
}

function responseOk(extra = {}) {
    return {
        success: true,
        ...extra
    };
}

/* ================================================================
 * 3. PROFILE AND AUTHORIZATION HELPERS
 * ================================================================ */

async function getUserProfile(uid) {
    const snapshot = await db
        .collection(COLLECTIONS.USERS)
        .doc(uid)
        .get();

    if (!snapshot.exists) {
        throw new HttpsError(
            "permission-denied",
            "ไม่พบข้อมูลผู้ใช้งานในระบบ"
        );
    }

    const profile = snapshot.data() || {};

    if (!isActiveStatus(profile)) {
        throw new HttpsError(
            "permission-denied",
            "บัญชีนี้ถูกระงับการใช้งาน"
        );
    }

    if (!ALLOWED_ROLES.includes(cleanString(profile.role, 40).toLowerCase())) {
        throw new HttpsError(
            "permission-denied",
            "บัญชีนี้ไม่มีสิทธิ์ใช้งานระบบ"
        );
    }

    return {
        ...profile,
        uid,
        id: uid
    };
}

async function requireAdmin(request) {
    const uid = requireUid(request);
    const profile = await getUserProfile(uid);

    if (!isAdminRole(profile)) {
        throw new HttpsError(
            "permission-denied",
            "เฉพาะผู้ดูแลระบบเท่านั้นที่ดำเนินการนี้ได้"
        );
    }

    return {
        uid,
        profile
    };
}

async function requireActiveUser(request) {
    const uid = requireUid(request);
    const profile = await getUserProfile(uid);

    return {
        uid,
        profile
    };
}

async function requireAlbumManagerOrAdmin(request) {
    const authData = await requireActiveUser(request);

    if (
        !isAdminRole(authData.profile) &&
        !isAlbumManagerRole(authData.profile)
    ) {
        throw new HttpsError(
            "permission-denied",
            "ไม่มีสิทธิ์จัดการอัลบั้ม"
        );
    }

    return authData;
}

function assertCanAccessOrganization(profile, organizationId) {
    if (isAdminRole(profile)) {
        return;
    }

    const ownOrganizationId = cleanString(
        profile.organizationId || profile.orgId,
        180
    );

    if (
        !ownOrganizationId ||
        ownOrganizationId !== cleanString(organizationId, 180)
    ) {
        throw new HttpsError(
            "permission-denied",
            "คุณไม่มีสิทธิ์เข้าถึงหน่วยงานนี้"
        );
    }
}

async function getOrganization(organizationId) {
    const id = normalizeId(organizationId, "รหัสหน่วยงาน");

    const snapshot = await db
        .collection(COLLECTIONS.ORGANIZATIONS)
        .doc(id)
        .get();

    if (!snapshot.exists) {
        throw new HttpsError(
            "not-found",
            "ไม่พบหน่วยงานที่ระบุ"
        );
    }

    return {
        id: snapshot.id,
        ...snapshot.data()
    };
}

async function getAlbum(albumId) {
    const id = normalizeId(albumId, "รหัสอัลบั้ม");

    const snapshot = await db
        .collection(COLLECTIONS.ALBUMS)
        .doc(id)
        .get();

    if (!snapshot.exists) {
        throw new HttpsError(
            "not-found",
            "ไม่พบอัลบั้มที่ระบุ"
        );
    }

    return {
        id: snapshot.id,
        ...snapshot.data()
    };
}

async function assertCanManageAlbum(profile, album) {
    if (isAdminRole(profile)) {
        return;
    }

    if (!isAlbumManagerRole(profile)) {
        throw new HttpsError(
            "permission-denied",
            "ไม่มีสิทธิ์จัดการอัลบั้ม"
        );
    }

    assertCanAccessOrganization(profile, album.organizationId);
}

async function assertAlbumOrganization(profile, organizationId) {
    const id = normalizeId(organizationId, "รหัสหน่วยงาน");

    assertCanAccessOrganization(profile, id);

    await getOrganization(id);

    return id;
}

async function listPhotosForAlbum(albumId) {
    const id = normalizeId(albumId, "รหัสอัลบั้ม");

    const snapshot = await db
        .collection(COLLECTIONS.PHOTOS)
        .where("albumId", "==", id)
        .get();

    return snapshot.docs
        .map(document => serializeDocument(document))
        .filter(photo => photo && photo.status !== "deleted")
        .sort((a, b) => {
            const first = safeInteger(a.order, 0);
            const second = safeInteger(b.order, 0);

            if (first !== second) {
                return first - second;
            }

            return String(a.id).localeCompare(String(b.id));
        });
}

/* ================================================================
 * 4. COUNTERS AND SEQUENCE HELPERS
 * ================================================================ */

async function reserveUserSequence() {
    const counterReference = db
        .collection(COLLECTIONS.SYSTEM)
        .doc("counters");

    return db.runTransaction(async transaction => {
        const snapshot = await transaction.get(counterReference);
        const data = snapshot.exists ? snapshot.data() : {};

        const current = safeInteger(data.userSequence, 0);
        const next = current + 1;

        transaction.set(
            counterReference,
            {
                userSequence: next,
                updatedAt: serverTimestamp()
            },
            {
                merge: true
            }
        );

        return next;
    });
}

async function setAlbumPhotoCount(albumId, count) {
    const id = normalizeId(albumId, "รหัสอัลบั้ม");

    await db.collection(COLLECTIONS.ALBUMS).doc(id).set(
        {
            photoCount: Math.max(0, safeInteger(count, 0)),
            updatedAt: serverTimestamp()
        },
        {
            merge: true
        }
    );
}

async function recountAlbumPhotos(albumId) {
    const id = normalizeId(albumId, "รหัสอัลบั้ม");

    const snapshot = await db
        .collection(COLLECTIONS.PHOTOS)
        .where("albumId", "==", id)
        .get();

    const count = snapshot.docs.filter(document => {
        const data = document.data() || {};

        return data.status !== "deleted";
    }).length;

    await setAlbumPhotoCount(id, count);

    return count;
}

/* ================================================================
 * 5. DASHBOARD INITIALIZATION
 * ================================================================ */

async function handleDashboardInit(request) {
    const { uid, profile } = await requireActiveUser(request);

    const organizationsSnapshot = await db
        .collection(COLLECTIONS.ORGANIZATIONS)
        .get();

    const allOrganizations = organizationsSnapshot.docs
        .map(document => serializeDocument(document))
        .filter(Boolean);

    const organizations = isAdminRole(profile)
        ? allOrganizations
        : allOrganizations.filter(org => {
            return String(org.id) === String(profile.organizationId || profile.orgId || "");
        });

    const usersSnapshot = isAdminRole(profile)
        ? await db.collection(COLLECTIONS.USERS).get()
        : null;

    const users = usersSnapshot
        ? usersSnapshot.docs
            .map(document => serializeDocument(document))
            .filter(Boolean)
            .map(user => ({
                id: user.id,
                uid: user.uid || user.id,
                displayName: user.displayName || user.fullName || user.name || "",
                fullName: user.fullName || user.displayName || user.name || "",
                username: user.username || "",
                email: user.email || "",
                organizationId: user.organizationId || "",
                role: user.role || "album_manager",
                status: user.status || "active",
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
                passwordChangedAt: user.passwordChangedAt || null
            }))
        : [];

    const albumsSnapshot = await db
        .collection(COLLECTIONS.ALBUMS)
        .get();

    const albums = albumsSnapshot.docs
        .map(document => serializeDocument(document))
        .filter(Boolean)
        .filter(album => {
            if (isAdminRole(profile)) {
                return true;
            }

            return String(album.organizationId || "") ===
                String(profile.organizationId || profile.orgId || "");
        });

    const categoriesSnapshot = await db
        .collection(COLLECTIONS.CATEGORIES)
        .get();

    const categories = categoriesSnapshot.docs
        .map(document => serializeDocument(document))
        .filter(Boolean)
        .filter(category => {
            if (isAdminRole(profile)) {
                return true;
            }

            const organizationId = category.organizationId;

            return !organizationId ||
                String(organizationId) === String(profile.organizationId || profile.orgId || "");
        });

    const photosSnapshot = await db
        .collection(COLLECTIONS.PHOTOS)
        .get();

    const visibleAlbumIds = new Set(albums.map(album => album.id));

    const photos = photosSnapshot.docs
        .map(document => serializeDocument(document))
        .filter(Boolean)
        .filter(photo => {
            return (
                visibleAlbumIds.has(String(photo.albumId)) &&
                photo.status !== "deleted"
            );
        });

    const safeProfile = {
        uid,
        id: uid,
        displayName: profile.displayName || profile.fullName || profile.name || "",
        fullName: profile.fullName || profile.displayName || profile.name || "",
        name: profile.name || profile.displayName || profile.fullName || "",
        username: profile.username || "",
        email: profile.email || request.auth.token.email || "",
        role: profile.role,
        status: profile.status || "active",
        organizationId: profile.organizationId || profile.orgId || "",
        photoURL: profile.photoURL || profile.avatarUrl || "",
        createdAt: toIsoDate(profile.createdAt),
        updatedAt: toIsoDate(profile.updatedAt),
        passwordChangedAt: toIsoDate(profile.passwordChangedAt)
    };

    return responseOk({
        profile: safeProfile,
        organizations,
        orgs: organizations,
        users,
        albums,
        photos,
        categories,
        stats: {
            albumCount: albums.length,
            photoCount: photos.length,
            organizationCount: organizations.length,
            userCount: users.length
        }
    });
}

/* ================================================================
 * 6. ALBUM CRUD
 * ================================================================ */

async function handleSaveAlbum(request) {
    const { uid, profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลอัลบั้ม");

    const albumId = cleanString(payload.id || payload.albumId, 180);
    const title = requireString(payload.title, "ชื่ออัลบั้ม", MAX_NAME_LENGTH);
    const description = cleanString(payload.description, MAX_DESCRIPTION_LENGTH);
    const organizationId = await assertAlbumOrganization(
        profile,
        payload.organizationId
    );

    const categoryId = cleanString(payload.categoryId, 180);
    const coverUrl = normalizeHttpsUrl(payload.coverUrl || "", "URL ภาพปก");

    const requestedStatus = validateAlbumStatus(payload.status || "draft");

    let reference;
    let previousData = null;

    if (albumId) {
        reference = db.collection(COLLECTIONS.ALBUMS).doc(albumId);

        const snapshot = await reference.get();

        if (!snapshot.exists) {
            throw new HttpsError(
                "not-found",
                "ไม่พบอัลบั้มที่ต้องการแก้ไข"
            );
        }

        previousData = snapshot.data() || {};

        await assertCanManageAlbum(
            profile,
            {
                id: snapshot.id,
                ...previousData
            }
        );

        if (
            !isAdminRole(profile) &&
            String(previousData.organizationId || "") !== organizationId
        ) {
            throw new HttpsError(
                "permission-denied",
                "ผู้จัดการอัลบั้มไม่สามารถย้ายอัลบั้มไปหน่วยงานอื่นได้"
            );
        }
    } else {
        reference = db.collection(COLLECTIONS.ALBUMS).doc();
    }

    const data = {
        title,
        description,
        organizationId,
        categoryId: categoryId || null,
        coverUrl: coverUrl || previousData?.coverUrl || "",
        status: previousData?.status === "published"
            ? previousData.status
            : requestedStatus,
        photoCount: safeInteger(previousData?.photoCount, 0),
        createdBy: previousData?.createdBy || uid,
        createdAt: previousData?.createdAt || serverTimestamp(),
        updatedAt: serverTimestamp()
    };

    if (categoryId) {
        const categorySnapshot = await db
            .collection(COLLECTIONS.CATEGORIES)
            .doc(categoryId)
            .get();

        if (!categorySnapshot.exists) {
            throw new HttpsError(
                "not-found",
                "ไม่พบหมวดหมู่ที่เลือก"
            );
        }
    }

    await reference.set(data, {
        merge: true
    });

    const savedSnapshot = await reference.get();
    const savedAlbum = serializeDocument(savedSnapshot);

    return responseOk({
        id: reference.id,
        albumId: reference.id,
        album: savedAlbum,
        message: "บันทึกอัลบั้มสำเร็จ"
    });
}

async function handleDeleteAlbum(request) {
    const { profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const albumId = normalizeId(
        payload.albumId || payload.id,
        "รหัสอัลบั้ม"
    );

    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    const photoSnapshot = await db
        .collection(COLLECTIONS.PHOTOS)
        .where("albumId", "==", albumId)
        .get();

    const photoChunks = chunkArray(photoSnapshot.docs, MAX_BATCH_WRITES);

    for (const chunk of photoChunks) {
        const batch = db.batch();

        for (const photoDocument of chunk) {
            batch.delete(photoDocument.ref);
        }

        await batch.commit();
    }

    await db.collection(COLLECTIONS.ALBUMS).doc(albumId).delete();

    return responseOk({
        albumId,
        deletedPhotoCount: photoSnapshot.size,
        message: "ลบอัลบั้มสำเร็จ"
    });
}

async function handlePublishAlbum(request) {
    const { profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const albumId = normalizeId(
        payload.albumId || payload.id,
        "รหัสอัลบั้ม"
    );

    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    const photos = await listPhotosForAlbum(albumId);

    const readyPhotos = photos.filter(photo => {
        return Boolean(
            photo.url &&
            /^https:\/\//i.test(photo.url) &&
            photo.status !== "deleted"
        );
    });

    if (readyPhotos.length < 1) {
        throw new HttpsError(
            "failed-precondition",
            "ไม่สามารถเผยแพร่อัลบั้มที่ไม่มีรูปภาพได้"
        );
    }

    const coverUrl = album.coverUrl || readyPhotos[0].url;

    await db.collection(COLLECTIONS.ALBUMS).doc(albumId).set(
        {
            status: "published",
            coverUrl,
            photoCount: readyPhotos.length,
            publishedAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            publishedBy: profile.uid
        },
        {
            merge: true
        }
    );

    const updated = await getAlbum(albumId);

    return responseOk({
        albumId,
        album: serializeData(updated, albumId),
        message: "เผยแพร่อัลบั้มสำเร็จ"
    });
}

async function handleListAlbumPhotos(request) {
    const { profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const albumId = normalizeId(
        payload.albumId || payload.id,
        "รหัสอัลบั้ม"
    );

    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    const photos = await listPhotosForAlbum(albumId);

    return responseOk({
        albumId,
        photos,
        count: photos.length
    });
}

/* ================================================================
 * 7. PHOTO CRUD AND ORDERING
 * ================================================================ */

function validatePhotoPayload(photo, index) {
    requireObject(photo, `รูปภาพลำดับที่ ${index + 1}`);

    const url = normalizeHttpsUrl(photo.url, "URL รูปภาพ");

    if (!url) {
        throw new HttpsError(
            "invalid-argument",
            `รูปภาพลำดับที่ ${index + 1} ไม่มี URL`
        );
    }

    const displayUrl = normalizeHttpsUrl(
        photo.displayUrl || photo.url,
        "URL แสดงผล"
    );

    const thumbnailUrl = normalizeHttpsUrl(
        photo.thumbnailUrl || photo.displayUrl || photo.url,
        "URL ภาพย่อ"
    );

    return {
        url,
        displayUrl: displayUrl || url,
        thumbnailUrl: thumbnailUrl || displayUrl || url,
        filename: cleanString(photo.filename || `image-${index + 1}`, 255),
        caption: cleanString(photo.caption, 1000),
        order: safeInteger(photo.order, index)
    };
}

async function handleSaveAlbumPhotos(request) {
    const { uid, profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลรูปภาพ");

    const albumId = normalizeId(payload.albumId, "รหัสอัลบั้ม");
    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    if (!Array.isArray(payload.photos)) {
        throw new HttpsError(
            "invalid-argument",
            "photos ต้องเป็น Array"
        );
    }

    if (payload.photos.length > MAX_PHOTOS_PER_REQUEST) {
        throw new HttpsError(
            "invalid-argument",
            `ส่งรูปภาพได้ครั้งละไม่เกิน ${MAX_PHOTOS_PER_REQUEST} รูป`
        );
    }

    const validatedPhotos = payload.photos.map(validatePhotoPayload);

    const createdPhotos = [];

    /*
     * ใช้ ID ใหม่สำหรับภาพที่เพิ่มผ่าน saveAlbumPhotos
     * ไม่ใช้ URL เป็นตัวระบุเอกลักษณ์ เพราะอัลบั้มรองรับการทำซ้ำภาพ
     */
    const batch = db.batch();

    for (const photo of validatedPhotos) {
        const photoReference = db.collection(COLLECTIONS.PHOTOS).doc();

        const photoData = {
            albumId,
            organizationId: album.organizationId,
            url: photo.url,
            displayUrl: photo.displayUrl,
            thumbnailUrl: photo.thumbnailUrl,
            filename: photo.filename,
            caption: photo.caption,
            order: photo.order,
            status: "ready",
            createdBy: uid,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp()
        };

        batch.set(photoReference, photoData);

        createdPhotos.push({
            id: photoReference.id,
            ...photoData,
            createdAt: null,
            updatedAt: null
        });
    }

    if (validatedPhotos.length) {
        await batch.commit();

        await recountAlbumPhotos(albumId);
    }

    return responseOk({
        albumId,
        photos: createdPhotos,
        count: createdPhotos.length,
        message: "บันทึกรูปภาพสำเร็จ"
    });
}

async function handleDeletePhotos(request) {
    const { profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const albumId = normalizeId(payload.albumId, "รหัสอัลบั้ม");
    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    const requestedIds = uniqueStrings(
        payload.photoIds ||
        payload.ids ||
        (payload.photoId ? [payload.photoId] : [])
    );

    if (!requestedIds.length) {
        throw new HttpsError(
            "invalid-argument",
            "กรุณาระบุรูปภาพที่ต้องการลบ"
        );
    }

    const references = requestedIds.map(id =>
        db.collection(COLLECTIONS.PHOTOS).doc(id)
    );

    const snapshots = await db.getAll(...references);
    const toDelete = [];

    for (const snapshot of snapshots) {
        if (!snapshot.exists) {
            continue;
        }

        const photo = snapshot.data() || {};

        if (String(photo.albumId) !== albumId) {
            throw new HttpsError(
                "permission-denied",
                "พบรูปภาพที่ไม่ได้อยู่ในอัลบั้มนี้"
            );
        }

        toDelete.push(snapshot.ref);
    }

    for (const chunk of chunkArray(toDelete, MAX_BATCH_WRITES)) {
        const batch = db.batch();

        for (const reference of chunk) {
            batch.delete(reference);
        }

        await batch.commit();
    }

    const photoCount = await recountAlbumPhotos(albumId);

    return responseOk({
        albumId,
        deletedCount: toDelete.length,
        photoCount,
        message: "ลบรูปภาพสำเร็จ"
    });
}

async function handleReorderPhotos(request) {
    const { profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const albumId = normalizeId(payload.albumId, "รหัสอัลบั้ม");
    const album = await getAlbum(albumId);

    await assertCanManageAlbum(profile, album);

    if (!Array.isArray(payload.photoIds)) {
        throw new HttpsError(
            "invalid-argument",
            "photoIds ต้องเป็น Array"
        );
    }

    const photoIds = uniqueStrings(payload.photoIds);

    if (photoIds.length !== payload.photoIds.length) {
        throw new HttpsError(
            "invalid-argument",
            "พบรหัสรูปภาพซ้ำกันในรายการเรียงลำดับ"
        );
    }

    if (photoIds.length > 5000) {
        throw new HttpsError(
            "invalid-argument",
            "อัลบั้มมีรูปภาพมากเกินไปสำหรับคำขอเรียงลำดับครั้งเดียว"
        );
    }

    if (!photoIds.length) {
        return responseOk({
            albumId,
            count: 0,
            message: "ไม่มีรูปภาพให้จัดเรียง"
        });
    }

    const photoReferences = photoIds.map(id =>
        db.collection(COLLECTIONS.PHOTOS).doc(id)
    );

    const snapshots = await db.getAll(...photoReferences);

    for (let index = 0; index < snapshots.length; index++) {
        const snapshot = snapshots[index];

        if (!snapshot.exists) {
            throw new HttpsError(
                "not-found",
                "ไม่พบรูปภาพบางรายการในอัลบั้ม"
            );
        }

        const photo = snapshot.data() || {};

        if (String(photo.albumId) !== albumId) {
            throw new HttpsError(
                "permission-denied",
                "มีรูปภาพที่ไม่ได้อยู่ในอัลบั้มนี้"
            );
        }
    }

    const updates = photoReferences.map((reference, index) => ({
        reference,
        order: index
    }));

    for (const chunk of chunkArray(updates, MAX_BATCH_WRITES)) {
        const batch = db.batch();

        for (const update of chunk) {
            batch.update(update.reference, {
                order: update.order,
                updatedAt: serverTimestamp()
            });
        }

        await batch.commit();
    }

    await db.collection(COLLECTIONS.ALBUMS).doc(albumId).set(
        {
            updatedAt: serverTimestamp()
        },
        {
            merge: true
        }
    );

    return responseOk({
        albumId,
        count: photoIds.length,
        message: "จัดเรียงรูปภาพสำเร็จ"
    });
}

/* ================================================================
 * 8. ORGANIZATION CRUD
 * ================================================================ */

async function handleSaveOrganization(request) {
    const { uid } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลหน่วยงาน");

    const organizationId = cleanString(
        payload.id || payload.organizationId,
        180
    );

    const name = requireString(
        payload.name || payload.organizationName,
        "ชื่อหน่วยงาน",
        MAX_NAME_LENGTH
    );

    const logoUrl = normalizeHttpsUrl(
        payload.logoUrl || payload.logoImageUrl || "",
        "URL โลโก้"
    );

    let reference;
    let previous = null;

    if (organizationId) {
        reference = db
            .collection(COLLECTIONS.ORGANIZATIONS)
            .doc(organizationId);

        const snapshot = await reference.get();

        if (!snapshot.exists) {
            throw new HttpsError(
                "not-found",
                "ไม่พบหน่วยงานที่ต้องการแก้ไข"
            );
        }

        previous = snapshot.data() || {};
    } else {
        reference = db.collection(COLLECTIONS.ORGANIZATIONS).doc();
    }

    const data = {
        name,
        organizationName: name,
        logoUrl: logoUrl || previous?.logoUrl || previous?.logoImageUrl || "",
        logoImageUrl: logoUrl || previous?.logoUrl || previous?.logoImageUrl || "",
        createdBy: previous?.createdBy || uid,
        createdAt: previous?.createdAt || serverTimestamp(),
        updatedAt: serverTimestamp()
    };

    await reference.set(data, {
        merge: true
    });

    const snapshot = await reference.get();
    const organization = serializeDocument(snapshot);

    return responseOk({
        id: reference.id,
        organizationId: reference.id,
        organization,
        message: "บันทึกหน่วยงานสำเร็จ"
    });
}

async function handleDeleteOrganization(request) {
    const { uid } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const organizationId = normalizeId(
        payload.id || payload.organizationId,
        "รหัสหน่วยงาน"
    );

    const organizationReference = db
        .collection(COLLECTIONS.ORGANIZATIONS)
        .doc(organizationId);

    const organizationSnapshot = await organizationReference.get();

    if (!organizationSnapshot.exists) {
        throw new HttpsError(
            "not-found",
            "ไม่พบหน่วยงานที่ต้องการลบ"
        );
    }

    const [usersSnapshot, albumsSnapshot] = await Promise.all([
        db.collection(COLLECTIONS.USERS)
            .where("organizationId", "==", organizationId)
            .get(),

        db.collection(COLLECTIONS.ALBUMS)
            .where("organizationId", "==", organizationId)
            .get()
    ]);

    if (!usersSnapshot.empty || !albumsSnapshot.empty) {
        throw new HttpsError(
            "failed-precondition",
            "ไม่สามารถลบหน่วยงานที่ยังมีผู้ใช้งานหรืออัลบั้มเกี่ยวข้องได้ กรุณาย้ายหรือลบข้อมูลที่เกี่ยวข้องก่อน"
        );
    }

    await organizationReference.delete();

    logger.info("Organization deleted", {
        organizationId,
        deletedBy: uid
    });

    return responseOk({
        id: organizationId,
        organizationId,
        message: "ลบหน่วยงานสำเร็จ"
    });
}

/* ================================================================
 * 9. USER CRUD
 * ================================================================ */

async function findAuthUserByUsername(username) {
    const email = usernameToEmail(username);

    try {
        return await firebaseAuth.getUserByEmail(email);
    } catch (error) {
        if (error?.code === "auth/user-not-found") {
            return null;
        }

        throw error;
    }
}

async function handleCreateUser(request) {
    const { uid: adminUid } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลผู้ใช้งาน");

    const displayName = requireString(
        payload.displayName || payload.fullName || payload.name,
        "ชื่อ-สกุล",
        MAX_NAME_LENGTH
    );

    const username = validateUsername(payload.username);

    const organizationId = normalizeId(
        payload.organizationId,
        "รหัสหน่วยงาน"
    );

    await getOrganization(organizationId);

    const existingAuthUser = await findAuthUserByUsername(username);

    if (existingAuthUser) {
        throw new HttpsError(
            "already-exists",
            "ชื่อผู้ใช้นี้มีอยู่ในระบบแล้ว"
        );
    }

    const existingUsernameQuery = await db
        .collection(COLLECTIONS.USERS)
        .where("username", "==", username)
        .limit(1)
        .get();

    if (!existingUsernameQuery.empty) {
        throw new HttpsError(
            "already-exists",
            "ชื่อผู้ใช้นี้มีอยู่ในระบบแล้ว"
        );
    }

    const sequence = await reserveUserSequence();
    const initialPassword = generateInitialPassword(sequence);
    const email = usernameToEmail(username);

    let createdAuthUser = null;

    try {
        createdAuthUser = await firebaseAuth.createUser({
            email,
            password: validatePassword(initialPassword),
            displayName,
            disabled: false,
            emailVerified: true
        });

        const userData = {
            uid: createdAuthUser.uid,
            username,
            email,
            displayName,
            fullName: displayName,
            name: displayName,
            role: "album_manager",
            status: "active",
            organizationId,
            createdBy: adminUid,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            passwordChangedAt: null,
            requirePasswordChange: true
        };

        await db
            .collection(COLLECTIONS.USERS)
            .doc(createdAuthUser.uid)
            .set(userData);

        logger.info("Album manager account created", {
            uid: createdAuthUser.uid,
            username,
            organizationId,
            createdBy: adminUid
        });

        return responseOk({
            uid: createdAuthUser.uid,
            id: createdAuthUser.uid,
            username,
            email,
            displayName,
            fullName: displayName,
            role: "album_manager",
            status: "active",
            organizationId,
            initialPassword,
            message: "สร้างบัญชีผู้ใช้งานสำเร็จ"
        });
    } catch (error) {
        if (createdAuthUser?.uid) {
            await firebaseAuth
                .deleteUser(createdAuthUser.uid)
                .catch(deleteError => {
                    logger.error("Failed to roll back created auth user", {
                        uid: createdAuthUser.uid,
                        message: deleteError?.message || String(deleteError)
                    });
                });
        }

        throw error;
    }
}

async function handleUpdateUser(request) {
    const { uid: adminUid } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลผู้ใช้งาน");

    const targetUid = normalizeId(
        payload.uid || payload.id,
        "รหัสผู้ใช้งาน"
    );

    const reference = db.collection(COLLECTIONS.USERS).doc(targetUid);
    const snapshot = await reference.get();

    if (!snapshot.exists) {
        throw new HttpsError(
            "not-found",
            "ไม่พบผู้ใช้งานที่ต้องการแก้ไข"
        );
    }

    const current = snapshot.data() || {};
    const updates = {
        updatedAt: serverTimestamp(),
        updatedBy: adminUid
    };

    if (
        payload.displayName !== undefined ||
        payload.fullName !== undefined ||
        payload.name !== undefined
    ) {
        const displayName = requireString(
            payload.displayName || payload.fullName || payload.name,
            "ชื่อ-สกุล",
            MAX_NAME_LENGTH
        );

        updates.displayName = displayName;
        updates.fullName = displayName;
        updates.name = displayName;

        await firebaseAuth.updateUser(targetUid, {
            displayName
        });
    }

    if (payload.organizationId !== undefined) {
        const organizationId = normalizeId(
            payload.organizationId,
            "รหัสหน่วยงาน"
        );

        await getOrganization(organizationId);

        updates.organizationId = organizationId;
    }

    if (payload.status !== undefined) {
        const status = validateUserStatus(payload.status);

        updates.status = status;

        await firebaseAuth.updateUser(targetUid, {
            disabled: status === "disabled"
        });
    }

    if (payload.role !== undefined) {
        const role = validateRole(payload.role);

        if (role === "admin" && !isAdminRole(current)) {
            throw new HttpsError(
                "failed-precondition",
                "ไม่สามารถเปลี่ยนสิทธิ์เป็นผู้ดูแลระบบผ่านการแก้ไขทั่วไปได้"
            );
        }

        updates.role = role;
    }

    if (payload.password !== undefined && payload.password !== "") {
        const password = validatePassword(payload.password);

        await firebaseAuth.updateUser(targetUid, {
            password
        });

        updates.requirePasswordChange = true;
        updates.passwordChangedAt = null;
    }

    await reference.set(updates, {
        merge: true
    });

    const updatedSnapshot = await reference.get();
    const updatedUser = serializeDocument(updatedSnapshot);

    return responseOk({
        id: targetUid,
        uid: targetUid,
        user: {
            id: targetUid,
            uid: targetUid,
            username: updatedUser.username || "",
            displayName: updatedUser.displayName || "",
            fullName: updatedUser.fullName || "",
            email: updatedUser.email || "",
            organizationId: updatedUser.organizationId || "",
            role: updatedUser.role || "album_manager",
            status: updatedUser.status || "active"
        },
        message: "แก้ไขข้อมูลผู้ใช้งานสำเร็จ"
    });
}

/* ================================================================
 * 10. CATEGORY CRUD
 * ================================================================ */

async function handleSaveCategory(request) {
    const { uid, profile } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลหมวดหมู่");

    const categoryId = cleanString(
        payload.id || payload.categoryId,
        180
    );

    const name = requireString(
        payload.name || payload.title,
        "ชื่อหมวดหมู่",
        MAX_NAME_LENGTH
    );

    const description = cleanString(payload.description, 1000);

    let reference;
    let previous = null;

    if (categoryId) {
        reference = db.collection(COLLECTIONS.CATEGORIES).doc(categoryId);

        const snapshot = await reference.get();

        if (!snapshot.exists) {
            throw new HttpsError(
                "not-found",
                "ไม่พบหมวดหมู่ที่ต้องการแก้ไข"
            );
        }

        previous = snapshot.data() || {};
    } else {
        reference = db.collection(COLLECTIONS.CATEGORIES).doc();
    }

    const data = {
        name,
        description,
        organizationId: cleanString(
            payload.organizationId || previous?.organizationId,
            180
        ) || null,
        createdBy: previous?.createdBy || uid,
        createdAt: previous?.createdAt || serverTimestamp(),
        updatedAt: serverTimestamp()
    };

    await reference.set(data, {
        merge: true
    });

    const snapshot = await reference.get();

    return responseOk({
        id: reference.id,
        categoryId: reference.id,
        category: serializeDocument(snapshot),
        message: "บันทึกหมวดหมู่สำเร็จ"
    });
}

async function handleDeleteCategory(request) {
    const { profile } = await requireAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลคำขอ");

    const categoryId = normalizeId(
        payload.id || payload.categoryId,
        "รหัสหมวดหมู่"
    );

    const categoryReference = db
        .collection(COLLECTIONS.CATEGORIES)
        .doc(categoryId);

    const snapshot = await categoryReference.get();

    if (!snapshot.exists) {
        throw new HttpsError(
            "not-found",
            "ไม่พบหมวดหมู่"
        );
    }

    const albumsSnapshot = await db
        .collection(COLLECTIONS.ALBUMS)
        .where("categoryId", "==", categoryId)
        .limit(1)
        .get();

    if (!albumsSnapshot.empty) {
        throw new HttpsError(
            "failed-precondition",
            "ไม่สามารถลบหมวดหมู่ที่ยังมีอัลบั้มใช้งานอยู่"
        );
    }

    await categoryReference.delete();

    return responseOk({
        categoryId,
        message: "ลบหมวดหมู่สำเร็จ"
    });
}

/* ================================================================
 * 11. IMG BB IMAGE UPLOAD
 * ================================================================ */

function decodeBase64Image(value) {
    const base64 = cleanString(value, MAX_IMAGE_BASE64_LENGTH);

    if (!base64) {
        throw new HttpsError(
            "invalid-argument",
            "ไม่พบข้อมูลรูปภาพ"
        );
    }

    /*
     * รองรับทั้ง base64 ปกติและ Data URI
     * หน้า dashboard.html ส่ง base64 ที่ตัด prefix แล้ว
     */
    const normalized = base64.replace(
        /^data:image\/[a-zA-Z0-9.+-]+;base64,/,
        ""
    );

    if (normalized.length > MAX_IMAGE_BASE64_LENGTH) {
        throw new HttpsError(
            "invalid-argument",
            "ข้อมูลรูปภาพมีขนาดใหญ่เกินไป"
        );
    }

    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(normalized)) {
        throw new HttpsError(
            "invalid-argument",
            "รูปแบบข้อมูลรูปภาพไม่ถูกต้อง"
        );
    }

    const buffer = Buffer.from(normalized, "base64");

    if (!buffer.length) {
        throw new HttpsError(
            "invalid-argument",
            "ไม่สามารถอ่านข้อมูลรูปภาพได้"
        );
    }

    if (buffer.length > MAX_IMAGE_BYTES) {
        throw new HttpsError(
            "invalid-argument",
            "รูปภาพมีขนาดเกิน 7 MB"
        );
    }

    return buffer;
}

function verifyImageMagicBytes(buffer, mimeType) {
    if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
        throw new HttpsError(
            "invalid-argument",
            "ไฟล์รูปภาพไม่สมบูรณ์"
        );
    }

    const type = cleanString(mimeType, 100).toLowerCase();

    const isJpeg =
        buffer[0] === 0xff &&
        buffer[1] === 0xd8 &&
        buffer[2] === 0xff;

    const isPng =
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47 &&
        buffer[4] === 0x0d &&
        buffer[5] === 0x0a &&
        buffer[6] === 0x1a &&
        buffer[7] === 0x0a;

    const isWebp =
        buffer.toString("ascii", 0, 4) === "RIFF" &&
        buffer.toString("ascii", 8, 12) === "WEBP";

    const matches =
        (type === "image/jpeg" && isJpeg) ||
        (type === "image/png" && isPng) ||
        (type === "image/webp" && isWebp);

    if (!matches) {
        throw new HttpsError(
            "invalid-argument",
            "ชนิดไฟล์ไม่ตรงกับข้อมูลรูปภาพจริง"
        );
    }
}

function sanitizeFilename(filename) {
    const value = cleanString(filename || "image", 255)
        .replace(/[^\wก-๙.\- ()]/g, "_");

    return value || "image";
}

async function uploadToImgBB(buffer, filename, apiKey) {
    if (!apiKey) {
        throw new HttpsError(
            "failed-precondition",
            "ยังไม่ได้ตั้งค่า Secret IMGBB_API_KEY"
        );
    }

    const form = new FormData();

    form.append(
        "image",
        buffer.toString("base64")
    );

    form.append(
        "name",
        sanitizeFilename(filename)
    );

    const endpoint = new URL("https://api.imgbb.com/1/upload");

    endpoint.searchParams.set("key", apiKey);

    let response;

    try {
        response = await fetch(endpoint.toString(), {
            method: "POST",
            body: form,
            signal: AbortSignal.timeout(45000)
        });
    } catch (error) {
        logger.error("ImgBB network request failed", {
            message: error?.message || String(error)
        });

        throw new HttpsError(
            "unavailable",
            "ไม่สามารถเชื่อมต่อบริการอัปโหลดรูปภาพได้"
        );
    }

    let result;

    try {
        result = await response.json();
    } catch {
        throw new HttpsError(
            "unavailable",
            "บริการอัปโหลดรูปภาพตอบกลับข้อมูลไม่ถูกต้อง"
        );
    }

    if (!response.ok || !result?.success || !result?.data?.url) {
        logger.error("ImgBB upload rejected", {
            httpStatus: response.status,
            error: result?.error?.message || "Unknown ImgBB error"
        });

        throw new HttpsError(
            "unavailable",
            "อัปโหลดรูปภาพไปยัง ImgBB ไม่สำเร็จ กรุณาลองใหม่"
        );
    }

    return {
        url: normalizeHttpsUrl(result.data.url, "URL รูปภาพ"),
        displayUrl: normalizeHttpsUrl(
            result.data.display_url || result.data.url,
            "URL แสดงผล"
        ),
        thumbnailUrl: normalizeHttpsUrl(
            result.data.thumb?.url ||
            result.data.medium?.url ||
            result.data.display_url ||
            result.data.url,
            "URL ภาพย่อ"
        ),
        deleteUrl: cleanString(result.data.delete_url || "", 4000),
        imageId: cleanString(result.data.id || "", 255),
        title: cleanString(result.data.title || "", 255),
        size: safeInteger(result.data.size, buffer.length)
    };
}

async function handleUploadImage(request) {
    const { uid, profile } = await requireAlbumManagerOrAdmin(request);
    const payload = requireObject(request.data, "ข้อมูลการอัปโหลด");

    const purpose = cleanString(payload.purpose || "photo", 30).toLowerCase();

    if (!["photo", "logo"].includes(purpose)) {
        throw new HttpsError(
            "invalid-argument",
            "purpose ต้องเป็น photo หรือ logo"
        );
    }

    const filename = sanitizeFilename(payload.filename);
    const mimeType = cleanString(payload.mimeType, 100).toLowerCase();

    if (!ALLOWED_IMAGE_TYPES.includes(mimeType)) {
        throw new HttpsError(
            "invalid-argument",
            "รองรับเฉพาะไฟล์ JPG, PNG และ WebP"
        );
    }

    const imageBuffer = decodeBase64Image(payload.base64);

    verifyImageMagicBytes(imageBuffer, mimeType);

    let album = null;
    let albumId = "";
    let organizationId = "";

    if (purpose === "photo") {
        albumId = normalizeId(payload.albumId, "รหัสอัลบั้ม");

        album = await getAlbum(albumId);

        await assertCanManageAlbum(profile, album);

        organizationId = cleanString(album.organizationId, 180);
    } else {
        if (!isAdminRole(profile)) {
            throw new HttpsError(
                "permission-denied",
                "เฉพาะผู้ดูแลระบบเท่านั้นที่อัปโหลดโลโก้หน่วยงานได้"
            );
        }

        organizationId = cleanString(
            payload.organizationId,
            180
        );

        /*
         * อนุญาตให้อัปโหลดโลโก้ก่อนสร้างเอกสารหน่วยงานได้
         * เมื่อมี organizationId จะตรวจว่าหน่วยงานมีอยู่จริง
         */
        if (organizationId) {
            await getOrganization(organizationId);
        }
    }

    const apiKey = SECRET_IMGBB_API_KEY.value();

    const image = await uploadToImgBB(
        imageBuffer,
        filename,
        apiKey
    );

    if (purpose === "logo") {
        if (organizationId) {
            await db
                .collection(COLLECTIONS.ORGANIZATIONS)
                .doc(organizationId)
                .set(
                    {
                        logoUrl: image.url,
                        logoImageUrl: image.url,
                        updatedAt: serverTimestamp()
                    },
                    {
                        merge: true
                    }
                );
        }

        logger.info("Organization logo uploaded", {
            uid,
            organizationId: organizationId || null
        });

        return responseOk({
            purpose: "logo",
            organizationId: organizationId || null,
            url: image.url,
            displayUrl: image.displayUrl,
            thumbnailUrl: image.thumbnailUrl,
            message: "อัปโหลดโลโก้สำเร็จ"
        });
    }

    /*
     * สร้างเอกสารรูปภาพทันทีที่ ImgBB อัปโหลดสำเร็จ
     * Dashboard จะนำ id นี้ไปใช้สำหรับการจัดเรียงและลบภาพ
     */
    const photoReference = db.collection(COLLECTIONS.PHOTOS).doc();

    const currentPhotoCount = await recountAlbumPhotos(albumId);

    const photoData = {
        albumId,
        organizationId,
        url: image.url,
        displayUrl: image.displayUrl,
        thumbnailUrl: image.thumbnailUrl,
        filename,
        caption: "",
        order: currentPhotoCount,
        status: "ready",
        imageHost: "imgbb",
        imageHostId: image.imageId,
        fileSize: image.size,
        mimeType,
        createdBy: uid,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp()
    };

    await photoReference.set(photoData);

    const finalCount = await recountAlbumPhotos(albumId);

    await db
        .collection(COLLECTIONS.ALBUMS)
        .doc(albumId)
        .set(
            {
                photoCount: finalCount,
                coverUrl: album.coverUrl || image.url,
                updatedAt: serverTimestamp()
            },
            {
                merge: true
            }
        );

    const photo = {
        id: photoReference.id,
        albumId,
        organizationId,
        url: image.url,
        displayUrl: image.displayUrl,
        thumbnailUrl: image.thumbnailUrl,
        filename,
        caption: "",
        order: currentPhotoCount,
        status: "ready",
        imageHost: "imgbb",
        imageHostId: image.imageId,
        fileSize: image.size,
        mimeType,
        createdAt: null,
        updatedAt: null
    };

    logger.info("Album photo uploaded", {
        uid,
        albumId,
        photoId: photoReference.id,
        fileSize: image.size
    });

    return responseOk({
        purpose: "photo",
        albumId,
        photo,
        id: photoReference.id,
        url: image.url,
        displayUrl: image.displayUrl,
        thumbnailUrl: image.thumbnailUrl,
        photoCount: finalCount,
        message: "อัปโหลดรูปภาพสำเร็จ"
    });
}

/* ================================================================
 * 12. FIRST ADMIN BOOTSTRAP
 * ================================================================ */

/**
 * เรียกฟังก์ชันนี้เฉพาะตอนติดตั้งระบบครั้งแรก
 *
 * ตัวอย่าง payload:
 *
 * {
 *   "setupKey": "ค่าที่ตั้งไว้ใน Secret BOOTSTRAP_KEY",
 *   "username": "sxaiq54",
 *   "password": "รหัสผ่านผู้ดูแลที่เลือกเอง",
 *   "displayName": "ชื่อผู้ดูแลระบบ"
 * }
 *
 * เมื่อสร้างผู้ดูแลระบบสำเร็จแล้ว ให้เปลี่ยน/หมุน BOOTSTRAP_KEY
 * และไม่ควรเปิดเผยค่าดังกล่าวใน GitHub หรือหน้าเว็บ
 */

async function handleBootstrapAdmin(request) {
    if (!request.auth) {
        throw new HttpsError(
            "unauthenticated",
            "ต้องเรียกใช้ฟังก์ชันตั้งค่าด้วยบริบทการยืนยันตัวตนที่ถูกต้อง"
        );
    }

    const payload = requireObject(request.data, "ข้อมูลตั้งค่าผู้ดูแล");

    const providedSetupKey = cleanString(payload.setupKey, 500);
    const expectedSetupKey = SECRET_BOOTSTRAP_KEY.value();

    if (!expectedSetupKey) {
        throw new HttpsError(
            "failed-precondition",
            "ยังไม่ได้ตั้งค่า Secret BOOTSTRAP_KEY"
        );
    }

    const suppliedHash = crypto
        .createHash("sha256")
        .update(providedSetupKey)
        .digest("hex");

    const expectedHash = crypto
        .createHash("sha256")
        .update(expectedSetupKey)
        .digest("hex");

    const keysMatch = crypto.timingSafeEqual(
        Buffer.from(suppliedHash, "hex"),
        Buffer.from(expectedHash, "hex")
    );

    if (!keysMatch) {
        logger.warn("Admin bootstrap rejected: invalid setup key", {
            callerUid: request.auth.uid
        });

        throw new HttpsError(
            "permission-denied",
            "รหัสตั้งค่าระบบไม่ถูกต้อง"
        );
    }

    const existingAdmins = await db
        .collection(COLLECTIONS.USERS)
        .where("role", "==", "admin")
        .limit(1)
        .get();

    if (!existingAdmins.empty) {
        throw new HttpsError(
            "failed-precondition",
            "มีบัญชีผู้ดูแลระบบอยู่แล้ว ไม่อนุญาตให้ตั้งค่าซ้ำ"
        );
    }

    const username = validateUsername(
        payload.username || DEFAULT_ADMIN_USERNAME
    );

    const password = validatePassword(payload.password);

    const displayName = cleanString(
        payload.displayName || DEFAULT_ADMIN_DISPLAY_NAME,
        MAX_NAME_LENGTH
    );

    const email = usernameToEmail(username);

    let existingAuthUser = null;

    try {
        existingAuthUser = await firebaseAuth.getUserByEmail(email);
    } catch (error) {
        if (error?.code !== "auth/user-not-found") {
            throw error;
        }
    }

    let authUser = existingAuthUser;
    let createdByThisRequest = false;

    try {
        if (!authUser) {
            authUser = await firebaseAuth.createUser({
                email,
                password,
                displayName,
                emailVerified: true,
                disabled: false
            });

            createdByThisRequest = true;
        } else {
            await firebaseAuth.updateUser(authUser.uid, {
                password,
                displayName,
                disabled: false,
                emailVerified: true
            });
        }

        const userReference = db
            .collection(COLLECTIONS.USERS)
            .doc(authUser.uid);

        const profileSnapshot = await userReference.get();

        if (profileSnapshot.exists) {
            throw new HttpsError(
                "already-exists",
                "บัญชีนี้มีข้อมูลผู้ใช้ใน Firestore อยู่แล้ว"
            );
        }

        await userReference.set({
            uid: authUser.uid,
            username,
            email,
            displayName,
            fullName: displayName,
            name: displayName,
            role: "admin",
            status: "active",
            organizationId: null,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
            passwordChangedAt: serverTimestamp(),
            requirePasswordChange: false,
            bootstrapCreated: true
        });

        logger.info("Initial administrator created", {
            uid: authUser.uid,
            username
        });

        return responseOk({
            uid: authUser.uid,
            id: authUser.uid,
            username,
            email,
            displayName,
            role: "admin",
            status: "active",
            message: "ตั้งค่าบัญชีผู้ดูแลระบบสำเร็จ"
        });
    } catch (error) {
        if (createdByThisRequest && authUser?.uid) {
            await firebaseAuth
                .deleteUser(authUser.uid)
                .catch(rollbackError => {
                    logger.error("Admin bootstrap rollback failed", {
                        uid: authUser.uid,
                        message: rollbackError?.message || String(rollbackError)
                    });
                });
        }

        throw error;
    }
}

/* ================================================================
 * 13. PASSWORD-CHANGE MARKER
 * ================================================================ */

async function handleMarkPasswordChanged(request) {
    const uid = requireUid(request);

    const targetUid = cleanString(
        request.data?.uid,
        180
    ) || uid;

    if (targetUid !== uid) {
        throw new HttpsError(
            "permission-denied",
            "ไม่สามารถเปลี่ยนสถานะรหัสผ่านของบัญชีอื่นได้"
        );
    }

    const profile = await getUserProfile(uid);

    await db
        .collection(COLLECTIONS.USERS)
        .doc(uid)
        .set(
            {
                passwordChangedAt: serverTimestamp(),
                requirePasswordChange: false,
                updatedAt: serverTimestamp()
            },
            {
                merge: true
            }
        );

    logger.info("Password change recorded", {
        uid,
        role: profile.role
    });

    return responseOk({
        uid,
        passwordChanged: true,
        message: "บันทึกสถานะการเปลี่ยนรหัสผ่านสำเร็จ"
    });
}

/* ================================================================
 * 14. PUBLIC GALLERY API
 * ================================================================ */

/**
 * Public endpoint สำหรับ index.html
 *
 * GET:
 *   /publicGallery
 *   /publicGallery?albumId=ALBUM_ID
 *
 * Query:
 *   albumId (optional)
 *   limit (optional; max 50)
 *
 * คืนเฉพาะอัลบั้มที่เผยแพร่แล้ว
 * ไม่ส่งข้อมูลบัญชีผู้ใช้หรือข้อมูลส่วนตัวกลับไป
 */

async function getPublishedAlbums(options = {}) {
    const requestedLimit = safeInteger(options.limit, 20);
    const limit = Math.min(Math.max(requestedLimit, 1), 50);

    const albumId = cleanString(options.albumId, 180);

    if (albumId) {
        const album = await getAlbum(albumId);

        if (album.status !== "published") {
            return [];
        }

        return [album];
    }

    const snapshot = await db
        .collection(COLLECTIONS.ALBUMS)
        .where("status", "==", "published")
        .limit(limit)
        .get();

    return snapshot.docs
        .map(document => serializeDocument(document))
        .filter(Boolean)
        .sort((a, b) => {
            const first = new Date(a.publishedAt || a.updatedAt || 0).getTime();
            const second = new Date(b.publishedAt || b.updatedAt || 0).getTime();

            return second - first;
        });
}

async function buildPublicAlbum(album) {
    const photos = await listPhotosForAlbum(album.id);

    const publicPhotos = photos
        .filter(photo => photo.status !== "deleted")
        .map(photo => ({
            id: photo.id,
            albumId: album.id,
            url: photo.url || "",
            displayUrl: photo.displayUrl || photo.url || "",
            thumbnailUrl: photo.thumbnailUrl || photo.displayUrl || photo.url || "",
            filename: photo.filename || "",
            caption: photo.caption || "",
            order: safeInteger(photo.order, 0)
        }));

    return {
        id: album.id,
        title: album.title || "",
        description: album.description || "",
        organizationId: album.organizationId || "",
        categoryId: album.categoryId || null,
        coverUrl: album.coverUrl || publicPhotos[0]?.url || "",
        status: "published",
        photoCount: publicPhotos.length,
        createdAt: album.createdAt || null,
        updatedAt: album.updatedAt || null,
        publishedAt: album.publishedAt || null,
        photos: publicPhotos
    };
}

exports.publicGallery = onRequest(
    {
        region: REGION,
        cors: true,
        timeoutSeconds: 60,
        memory: "256MiB"
    },
    async (request, response) => {
        if (request.method === "OPTIONS") {
            response.set("Access-Control-Allow-Origin", "*");
            response.set("Access-Control-Allow-Methods", "GET, OPTIONS");
            response.set("Access-Control-Allow-Headers", "Content-Type");
            response.status(204).send("");

            return;
        }

        if (request.method !== "GET") {
            response.set("Allow", "GET, OPTIONS");

            response.status(405).json({
                success: false,
                message: "Method Not Allowed"
            });

            return;
        }

        response.set("Access-Control-Allow-Origin", "*");
        response.set("Cache-Control", "public, max-age=30, s-maxage=60");

        try {
            const albumId = cleanString(request.query.albumId, 180);
            const limit = safeInteger(request.query.limit, 20);

            const albums = await getPublishedAlbums({
                albumId,
                limit
            });

            const publicAlbums = [];

            for (const album of albums) {
                publicAlbums.push(await buildPublicAlbum(album));
            }

            response.status(200).json({
                success: true,
                albums: publicAlbums,
                count: publicAlbums.length
            });
        } catch (error) {
            logger.error("Public gallery request failed", {
                message: error?.message || String(error)
            });

            response.status(500).json({
                success: false,
                message: "ไม่สามารถโหลดอัลบั้มได้ในขณะนี้"
            });
        }
    }
);

/* ================================================================
 * 15. HEALTH CHECK
 * ================================================================ */

exports.healthCheck = onRequest(
    {
        region: REGION,
        cors: true,
        timeoutSeconds: 15,
        memory: "128MiB"
    },
    async (request, response) => {
        if (request.method !== "GET") {
            response.set("Allow", "GET");
            response.status(405).json({
                success: false,
                message: "Method Not Allowed"
            });

            return;
        }

        try {
            await db
                .collection(COLLECTIONS.SYSTEM)
                .doc("health")
                .get();

            response.status(200).json({
                success: true,
                service: "ActiGallery",
                region: REGION,
                timestamp: new Date().toISOString(),
                services: {
                    firebaseAdmin: "ok",
                    firestore: "ok"
                }
            });
        } catch (error) {
            logger.error("Health check failed", {
                message: error?.message || String(error)
            });

            response.status(503).json({
                success: false,
                service: "ActiGallery",
                timestamp: new Date().toISOString(),
                message: "บริการบางส่วนไม่พร้อมใช้งาน"
            });
        }
    }
);

/* ================================================================
 * 16. DASHBOARD ACTION ROUTER
 * ================================================================ */

/**
 * Action names used by dashboard.html:
 *
 * dashboardInit
 * saveAlbum
 * publishAlbum
 * deleteAlbum
 * listAlbumPhotos
 * saveAlbumPhotos
 * deletePhotos
 * reorderPhotos
 * saveOrganization
 * deleteOrganization
 * saveCategory
 * deleteCategory
 * createUser
 * updateUser
 */

async function routeDashboardAction(request) {
    const payload = requireObject(request.data || {}, "ข้อมูลคำขอ");
    const action = cleanString(payload.action, 100);

    if (!action) {
        throw new HttpsError(
            "invalid-argument",
            "ไม่พบ action"
        );
    }

    switch (action) {
        case "dashboardInit":
            return handleDashboardInit(request);

        case "saveAlbum":
            return handleSaveAlbum(request);

        case "publishAlbum":
            return handlePublishAlbum(request);

        case "deleteAlbum":
            return handleDeleteAlbum(request);

        case "listAlbumPhotos":
            return handleListAlbumPhotos(request);

        case "saveAlbumPhotos":
            return handleSaveAlbumPhotos(request);

        case "deletePhotos":
            return handleDeletePhotos(request);

        case "reorderPhotos":
            return handleReorderPhotos(request);

        case "saveOrganization":
            return handleSaveOrganization(request);

        case "deleteOrganization":
            return handleDeleteOrganization(request);

        case "saveCategory":
            return handleSaveCategory(request);

        case "deleteCategory":
            return handleDeleteCategory(request);

        case "createUser":
            return handleCreateUser(request);

        case "updateUser":
            return handleUpdateUser(request);

        default:
            throw new HttpsError(
                "invalid-argument",
                `ไม่รู้จัก action: ${action}`
            );
    }
}

exports.dashboardApi = onCall(
    {
        region: REGION,
        timeoutSeconds: 120,
        memory: "512MiB",
        enforceAppCheck: false
    },
    async request => {
        try {
            return await routeDashboardAction(request);
        } catch (error) {
            const publicError = getPublicError(error);

            logger.warn("dashboardApi action failed", {
                action: request.data?.action || "",
                uid: request.auth?.uid || null,
                code: publicError.code,
                message: publicError.message
            });

            throw publicError;
        }
    }
);

/* ================================================================
 * 17. UPLOAD IMAGE CALLABLE
 * ================================================================ */

exports.uploadImage = onCall(
    {
        region: REGION,
        timeoutSeconds: 120,
        memory: "1GiB",
        secrets: [SECRET_IMGBB_API_KEY],
        enforceAppCheck: false
    },
    async request => {
        try {
            return await handleUploadImage(request);
        } catch (error) {
            const publicError = getPublicError(error);

            logger.warn("uploadImage failed", {
                uid: request.auth?.uid || null,
                purpose: request.data?.purpose || "",
                albumId: request.data?.albumId || null,
                code: publicError.code,
                message: publicError.message
            });

            throw publicError;
        }
    }
);

/* ================================================================
 * 18. BOOTSTRAP ADMIN CALLABLE
 * ================================================================ */

exports.bootstrapAdmin = onCall(
    {
        region: REGION,
        timeoutSeconds: 60,
        memory: "256MiB",
        secrets: [SECRET_BOOTSTRAP_KEY],
        enforceAppCheck: false
    },
    async request => {
        try {
            return await handleBootstrapAdmin(request);
        } catch (error) {
            const publicError = getPublicError(error);

            logger.warn("bootstrapAdmin failed", {
                callerUid: request.auth?.uid || null,
                code: publicError.code,
                message: publicError.message
            });

            throw publicError;
        }
    }
);

/* ================================================================
 * 19. MARK PASSWORD CHANGED CALLABLE
 * ================================================================ */

exports.markPasswordChanged = onCall(
    {
        region: REGION,
        timeoutSeconds: 30,
        memory: "256MiB",
        enforceAppCheck: false
    },
    async request => {
        try {
            return await handleMarkPasswordChanged(request);
        } catch (error) {
            const publicError = getPublicError(error);

            logger.warn("markPasswordChanged failed", {
                uid: request.auth?.uid || null,
                code: publicError.code,
                message: publicError.message
            });

            throw publicError;
        }
    }
);
