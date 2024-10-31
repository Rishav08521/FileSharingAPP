import File from '../models/File.js';
import bcrypt from 'bcrypt';

// Upload file with optional expiry date and password
export const uploadFile = async (req, res) => {
    try {
        const { expiryDate, password } = req.body;

        // Hash the password if provided
        let hashedPassword;
        if (password) {
            const salt = await bcrypt.genSalt(10);
            hashedPassword = await bcrypt.hash(password, salt);
        }

        const fileData = new File({
            path: req.file.path,
            name: req.file.originalname,
            expiryDate: expiryDate ? new Date(expiryDate) : null,
            password: hashedPassword || null,
        });

        const savedFile = await fileData.save();
        res.status(200).json({ path: savedFile.path });
    } catch (error) {
        console.error('Error uploading file:', error);
        res.status(500).json({ message: 'File upload failed' });
    }
};

// Get file with password protection and expiry check
export const getFile = async (req, res) => {
    try {
        const { password } = req.body;
        const file = await File.findById(req.params.fileId);

        if (!file) return res.status(404).send('File not found');
        if (file.expiryDate && file.expiryDate < new Date()) return res.status(410).send('File has expired');

        if (file.password) {
            const isPasswordMatch = await bcrypt.compare(password || '', file.password);
            if (!isPasswordMatch) return res.status(401).send('Incorrect password');
        }

        res.status(200).json({ path: file.path });
    } catch (error) {
        console.error('Error retrieving file:', error);
        res.status(500).send('Server error');
    }
};
