const path = require('path')
const crypto = require('crypto')
const express = require('express')
const cors = require('cors')
const sqlite3 = require('sqlite3').verbose()
const nodemailer = require('nodemailer')
const multer = require('multer')
const fs = require('fs')
require('dotenv').config({ path: path.join(__dirname, '.env') })

const app = express()
const port = process.env.PORT || 3001
const adminPassword = process.env.ADMIN_PASSWORD || 'change-me'
const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173'
const dbPath = process.env.DB_PATH || path.join(__dirname, 'data.db')
const emailUser = process.env.EMAIL_USER
const emailPass = process.env.EMAIL_PASS
const emailTo = process.env.EMAIL_TO

const db = new sqlite3.Database(dbPath)
const uploadDir = path.join(__dirname, 'uploads')

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true })
}

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')
      cb(null, `${Date.now()}-${safeName}`)
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
})

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      date TEXT NOT NULL,
      image_url TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  )
  db.run(
    `CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  )
  db.run(
    `CREATE TABLE IF NOT EXISTS media (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`,
  )
  db.all(`PRAGMA table_info(articles)`, (err, rows) => {
    if (err) {
      return
    }
    const hasImage = rows.some((row) => row.name === 'image_url')
    if (!hasImage) {
      db.run('ALTER TABLE articles ADD COLUMN image_url TEXT')
    }
  })
})

const allowedOrigins = corsOrigin
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes('*')) {
        return callback(null, true)
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true)
      }
      if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
        return callback(null, true)
      }
      return callback(null, false)
    },
  }),
)
app.use(express.json())
app.use('/uploads', express.static(uploadDir))

const activeTokens = new Set()

const transporter =
  emailUser && emailPass
    ? nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: emailUser,
          pass: emailPass,
        },
      })
    : null

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.replace('Bearer ', '')

  if (!token || !activeTokens.has(token)) {
    return res.status(401).json({ message: 'Unauthorized' })
  }

  return next()
}

app.post('/api/login', (req, res) => {
  const { password } = req.body || {}

  if (!password || password !== adminPassword) {
    return res.status(401).json({ message: 'Invalid password' })
  }

  const token = crypto.randomBytes(24).toString('hex')
  activeTokens.add(token)
  return res.json({ token })
})

app.get('/api/articles', (req, res) => {
  db.all(
    'SELECT id, title, content, date, image_url FROM articles ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' })
      }
      return res.json(rows)
    },
  )
})

app.post('/api/articles', requireAuth, (req, res) => {
  const { title, content, date, imageUrl } = req.body || {}

  if (!title || !content || !date) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const stmt = db.prepare(
    'INSERT INTO articles (title, content, date, image_url) VALUES (?, ?, ?, ?)',
  )
  stmt.run(title, content, date, imageUrl || null, function onInsert(err) {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    return res.json({
      id: this.lastID,
      title,
      content,
      date,
      image_url: imageUrl || null,
    })
  })
  stmt.finalize()
})

app.post('/api/contact', (req, res) => {
  const { name, phone, email, content } = req.body || {}

  if (!name || !phone || !email || !content) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  const stmt = db.prepare(
    'INSERT INTO messages (name, phone, email, content) VALUES (?, ?, ?, ?)',
  )
  stmt.run(name, phone, email, content, function onInsert(err) {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    if (transporter && emailTo) {
      transporter.sendMail({
        from: emailUser,
        to: emailTo,
        subject: `Mesaj nou de la ${name}`,
        text: `Nume: ${name}\nTelefon: ${phone}\nEmail: ${email}\n\n${content}`,
      })
    }
    return res.json({ success: true, id: this.lastID })
  })
  stmt.finalize()
})

app.get('/api/messages', requireAuth, (req, res) => {
  db.all(
    'SELECT id, name, phone, email, content, created_at FROM messages ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' })
      }
      return res.json(rows)
    },
  )
})

app.get('/api/media', (req, res) => {
  db.all('SELECT id, title, url FROM media ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    return res.json(rows)
  })
})

app.post('/api/media', requireAuth, (req, res) => {
  const { title, url } = req.body || {}

  if (!title || !url) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  db.get('SELECT COUNT(*) as count FROM media', (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    if (row && row.count >= 9) {
      return res.status(400).json({ message: 'Media limit reached' })
    }

    const stmt = db.prepare('INSERT INTO media (title, url) VALUES (?, ?)')
    stmt.run(title, url, function onInsert(insertErr) {
      if (insertErr) {
        return res.status(500).json({ message: 'Database error' })
      }
      return res.json({ id: this.lastID, title, url })
    })
    stmt.finalize()
  })
})

app.put('/api/media/:id', requireAuth, (req, res) => {
  const { id } = req.params
  const { title, url } = req.body || {}

  if (!title || !url) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  db.run(
    'UPDATE media SET title = ?, url = ? WHERE id = ?',
    [title, url, id],
    function onUpdate(err) {
      if (err) {
        return res.status(500).json({ message: 'Database error' })
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Not found' })
      }
      return res.json({ id: Number(id), title, url })
    },
  )
})

app.delete('/api/media/:id', requireAuth, (req, res) => {
  const { id } = req.params

  db.run('DELETE FROM media WHERE id = ?', [id], function onDelete(err) {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'Not found' })
    }
    return res.json({ success: true })
  })
})

app.put('/api/articles/:id', requireAuth, (req, res) => {
  const { id } = req.params
  const { title, content, date, imageUrl } = req.body || {}

  if (!title || !content || !date) {
    return res.status(400).json({ message: 'Missing fields' })
  }

  db.run(
    'UPDATE articles SET title = ?, content = ?, date = ?, image_url = ? WHERE id = ?',
    [title, content, date, imageUrl || null, id],
    function onUpdate(err) {
      if (err) {
        return res.status(500).json({ message: 'Database error' })
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'Not found' })
      }
      return res.json({
        id: Number(id),
        title,
        content,
        date,
        image_url: imageUrl || null,
      })
    },
  )
})

app.delete('/api/articles/:id', requireAuth, (req, res) => {
  const { id } = req.params

  db.run('DELETE FROM articles WHERE id = ?', [id], function onDelete(err) {
    if (err) {
      return res.status(500).json({ message: 'Database error' })
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: 'Not found' })
    }
    return res.json({ success: true })
  })
})

app.post('/api/uploads', requireAuth, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' })
  }
  const url = `/uploads/${req.file.filename}`
  return res.json({ url })
})

app.listen(port, () => {
  console.log(`API server running on http://localhost:${port}`)
})
