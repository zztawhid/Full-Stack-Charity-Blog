/**
 * File Upload Security Middleware
 * 
 * Protects against: Malicious file uploads, path traversal, code execution
 * 
 * How it works:
 * 1. Multer handles multipart form data with a file size limit (5 MB)
 * 2. Files are stored in memory first (not disk) for validation
 * 3. After upload, the MIME type is verified using the file-type library
 *    which reads the file's magic bytes — not the user-provided extension
 * 4. Only jpeg, png, and gif are allowed
 * 5. The file is renamed server-side using a UUID — the user-provided
 *    filename is NEVER used, preventing path traversal attacks
 * 6. The validated file is then written to the uploads directory
 */

const multer = require('multer');
const path   = require('path');
const fs     = require('fs');
const { v4: uuidv4 } = require('uuid');

const MAX_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 5242880; // 5MB

// Store in memory so we can validate before writing to disk
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: {
    fileSize: MAX_SIZE
  },
  fileFilter: (req, file, cb) => {
    // Preliminary check on the declared MIME type
    const allowed = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Only JPEG, PNG, and GIF images are allowed.'));
    }
    cb(null, true);
  }
});

/**
 * Validates the uploaded file's actual MIME type by reading its magic bytes
 * using the file-type library. Then saves with a UUID filename.
 * Returns the generated filename or null if no file was uploaded.
 * 
 * @param {Object} file - The multer file object (from req.file)
 * @returns {Promise<string|null>} The server-generated filename
 */
async function validateAndSaveFile(file) {
  if (!file) return null;

  // Dynamic import for file-type (v16 supports CommonJS require)
  const FileType = require('file-type');
  const typeResult = await FileType.fromBuffer(file.buffer);

  if (!typeResult) {
    throw new Error('Could not determine file type. Upload rejected.');
  }

  const allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
  if (!allowedMimes.includes(typeResult.mime)) {
    throw new Error(`File type ${typeResult.mime} is not allowed. Only JPEG, PNG, and GIF.`);
  }

  // Generate a server-side filename using UUID — never use the original name
  const ext = typeResult.ext; // e.g. 'jpg', 'png', 'gif'
  const filename = `${uuidv4()}.${ext}`;
  const uploadDir = path.join(__dirname, '..', process.env.UPLOAD_DIR || 'uploads');
  const filepath = path.join(uploadDir, filename);

  // Ensure upload directory exists
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  // Write validated file to disk
  fs.writeFileSync(filepath, file.buffer);

  return filename;
}

module.exports = { upload, validateAndSaveFile };
