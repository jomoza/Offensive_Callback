const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// Middleware para parsear el cuerpo de la solicitud
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// Configuración del almacenamiento de archivos con multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = process.env.UPLOAD_PATH || 'uploads';
        const id = req.query.ID || 'default';
        const dir = path.join(uploadPath, id);
        
      
        // Crear la carpeta de subida si no existe
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir); // Ruta donde se almacenarán los archivos
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        cb(null, `${file.originalname}-${uniqueSuffix}${path.extname(file.originalname)}`);
    },
});

// Configuración de multer
let uploadFile = multer({
    storage,
    limits: {
        fileSize: 5000 * 1024 * 1024, // Limite de 500 MB por archivo
    },
    fileFilter: (req, file, cb) => {
        return cb(null, true);
    },
});

// Define las funciones web dentro del objeto `webfuncs`
const webfuncs = {
    upload: (req, res) => {
        uploadFile.single('file')(req, res, async (err) => {
            if (err) {
                if (err.message === 'Unexpected end of form') {
                    console.warn("[5ELG-FILES] Unexpected end of file form.");
                } else {
                    console.error("[5ELG-ERROR] File upload error:", err);
                    return res.status(500).json({ message: 'Error al subir el archivo.', error: err.message });
                }
            }

            if (!req.file) {
                return res.status(400).json({ message: 'No se recibió ningún archivo.' });
            }

            // IGNORAR si el archivo es el PNG de respuesta de la herramienta
            const original = req.file.originalname || '';
            const filename = req.file.filename || '';
            if (
                original.startsWith('dealer.png') ||
                filename.startsWith('dealer.png') ||
                original.includes('.png?unjs=true') ||
                filename.includes('.png?unjs=true')
            ) {
                // Eliminar el archivo subido si existe
                try { fs.unlinkSync(req.file.path); } catch (e) {}
                return res.status(204).end(); // No Content, no hacer nada
            }

            // ...existing code...
            // Obtener el ID del formulario
            const fileId = req.query.ID;
            const uploadPath = process.env.UPLOAD_PATH || 'uploads';
            const dir = path.join(uploadPath, fileId || 'default');
            const uploadedFilePath = req.file.path;
            const uploadedFileBuffer = fs.readFileSync(uploadedFilePath);
            const crypto = require('crypto');
            const uploadedFileHash = crypto.createHash('sha256').update(uploadedFileBuffer).digest('hex');

            // Buscar archivos existentes en la carpeta y comparar hash
            const filesInDir = fs.readdirSync(dir);
            for (const fname of filesInDir) {
                const fpath = path.join(dir, fname);
                if (fpath === uploadedFilePath) continue; // skip self
                if (fs.statSync(fpath).isFile()) {
                    const buf = fs.readFileSync(fpath);
                    const hash = crypto.createHash('sha256').update(buf).digest('hex');
                    if (hash === uploadedFileHash) {
                        // Eliminar el archivo recién subido (duplicado)
                        fs.unlinkSync(uploadedFilePath);
                        return res.status(409).json({
                            message: 'Archivo duplicado: ya existe un archivo con el mismo contenido.',
                            file: {
                                originalname: req.file.originalname,
                                filename: fname,
                                path: fpath,
                                size: buf.length,
                                id: fileId,
                            },
                        });
                    }
                }
            }

            res.status(200).json({
                message: 'Archivo subido con éxito.',
                file: {
                    originalname: req.file.originalname,
                    filename: req.file.filename,
                    path: req.file.path,
                    size: req.file.size,
                    id: fileId,
                },
            });
        });
    },
    uploads: async (req, res) => {
        try {
            if (!req.files || req.files.length === 0) {
                return res.status(400).json({ message: 'No se subieron archivos.' });
            }
            const uploadedFiles = req.files.map((file) => ({
                originalname: file.originalname,
                filename: file.filename,
                path: file.path,
                size: file.size,
            }));
            res.status(200).json({
                message: 'Archivos subidos con éxito.',
                files: uploadedFiles,
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: 'Error al subir los archivos.', error: err.message });
        }    
    },
    uploadFromB64: async (req, res) => {
        try {
            const { filebase64, filename, ID } = req.body;
            if (!filebase64 || !filename || !ID) {
                return res.status(400).json({ message: 'Faltan parámetros necesarios.' });
            }

            const uploadPath = process.env.UPLOAD_DIR || 'uploads';
            const dir = path.join(uploadPath, ID);

            // Crear la carpeta de subida si no existe
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }

            const filePath = path.join(dir, filename);
            const fileBuffer = Buffer.from(filebase64, 'base64');

            fs.writeFileSync(filePath, fileBuffer);

            res.status(200).json({
                message: 'Archivo subido con éxito.',
                file: {
                    originalname: filename,
                    path: filePath,
                    size: fileBuffer.length,
                },
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ message: 'Error al subir el archivo desde base64.', error: err.message });
        }
    }
};

// Aplica multer directamente en las rutas
router.post('/file', (req, res, next) => {
    uploadFile.single('file')(req, res, (err) => {
        if (err) {
            console.error("[5ELG-ERROR] File upload error:", err);
            return res.status(500).json({ message: 'Error al subir el archivo.', error: err.message });
        }
        next();
    });
}, webfuncs.upload);

router.post('/file64', webfuncs.uploadFromB64);
router.post('/files', (req, res, next) => {
    uploadFile.array('files')(req, res, (err) => {
        if (err) {
            console.error("[5ELG-ERROR] File upload errors:", err);
            return res.status(500).json({ message: 'Error al subir los archivos.', error: err.message });
        }
        next();
    });
}, webfuncs.uploads);

module.exports = router;