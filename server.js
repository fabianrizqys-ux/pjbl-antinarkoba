export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Tangani preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Health check
    if (request.method === 'GET' && path === '/api/health') {
      return jsonResponse({ ok: true, message: 'Cloudflare Worker aktif' });
    }

    // Register
    if (request.method === 'POST' && path === '/api/register') {
      try {
        const { username, email, password } = await request.json();
        if (!username || !email || !password) {
          return jsonResponse({ error: 'Username, email, dan password wajib diisi.' }, 400);
        }

        const existing = await queryNeon(
          env.DATABASE_URL,
          'SELECT id FROM users WHERE username = $1 OR email = $2',
          [username, email]
        );
        if (existing.rows.length > 0) {
          return jsonResponse({ error: 'Username atau Email sudah terdaftar!' }, 400);
        }

        await queryNeon(
          env.DATABASE_URL,
          'INSERT INTO users (username, email, password, quiz_score) VALUES ($1, $2, $3, 0)',
          [username, email, password]
        );

        return jsonResponse({ message: 'Registrasi berhasil!' }, 201);
      } catch (err) {
        console.error('Register error:', err);
        return jsonResponse({ error: 'Terjadi kesalahan pada server.' }, 500);
      }
    }

    // Login
    if (request.method === 'POST' && path === '/api/login') {
      try {
        const { username, password } = await request.json();
        const result = await queryNeon(
          env.DATABASE_URL,
          'SELECT id, username, email, quiz_score, avatar_url FROM users WHERE username = $1 AND password = $2',
          [username, password]
        );

        if (result.rows.length > 0) {
          return jsonResponse({ success: true, user: result.rows[0] });
        }
        return jsonResponse({ error: 'Username atau Password salah!' }, 401);
      } catch (err) {
        console.error('Login error:', err);
        return jsonResponse({ error: 'Terjadi kesalahan pada server.' }, 500);
      }
    }

    // Google Login
    if (request.method === 'POST' && path === '/api/google-login') {
      try {
        const { token } = await request.json();
        const parts = (token || '').split('.');
        if (parts.length !== 3) {
          return jsonResponse({ error: 'Token Google tidak valid.' }, 400);
        }

        const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
        const decoded = atob(padded);
        const bytes = Uint8Array.from(decoded, (ch) => ch.charCodeAt(0));
        const googlePayload = JSON.parse(new TextDecoder().decode(bytes));

        const email = googlePayload.email;
        const name = googlePayload.name || email.split('@')[0];

        let userResult = await queryNeon(
          env.DATABASE_URL,
          'SELECT id, username, email, quiz_score, avatar_url FROM users WHERE email = $1',
          [email]
        );

        if (userResult.rows.length === 0) {
          userResult = await queryNeon(
            env.DATABASE_URL,
            'INSERT INTO users (username, email, password, quiz_score) VALUES ($1, $2, $3, 0) RETURNING id, username, email, quiz_score, avatar_url',
            [name, email, 'GOOGLE_AUTH_USER']
          );
        }

        return jsonResponse({ success: true, user: userResult.rows[0] });
      } catch (err) {
        console.error('Google Auth error:', err);
        return jsonResponse({ error: 'Gagal verifikasi token Google.' }, 400);
      }
    }

    // Step 1: Kirim Kode Verifikasi (OTP) ke Email via Resend / MailChannels API
    if (request.method === 'POST' && path === '/api/send-reset-code') {
      try {
        const { email } = await request.json();
        const userCheck = await queryNeon(env.DATABASE_URL, 'SELECT id FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length === 0) {
          return jsonResponse({ error: 'Email tidak ditemukan di database.' }, 404);
        }

        const verificationCode = Math.floor(1000 + Math.random() * 9000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 menit

        // Simpan OTP di tabel password_reset_otps (agar awet lintas request Worker)
        await ensureOtpTable(env.DATABASE_URL);
        await queryNeon(
          env.DATABASE_URL,
          `INSERT INTO password_reset_otps (email, code, expires_at)
           VALUES ($1, $2, $3)
           ON CONFLICT (email) DO UPDATE SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at`,
          [email, verificationCode, expiresAt]
        );

        await sendOtpEmail(env, email, verificationCode);

        return jsonResponse({
          success: true,
          message: `Kode verifikasi telah dikirim ke email ${email}. Silakan cek inbox atau folder spam.`
        });
      } catch (err) {
        console.error('Send reset code error:', err);
        return jsonResponse({
          error: 'Gagal mengirim email verifikasi. Pastikan RESEND_API_KEY & EMAIL_FROM sudah diatur di Worker.'
        }, 500);
      }
    }

    // Step 2: Verifikasi Kode & Ubah Password
    if (request.method === 'POST' && path === '/api/forgot-password') {
      try {
        const { email, code, newPassword } = await request.json();
        await ensureOtpTable(env.DATABASE_URL);

        const otpRes = await queryNeon(
          env.DATABASE_URL,
          'SELECT code, expires_at FROM password_reset_otps WHERE email = $1',
          [email]
        );

        const otpRow = otpRes.rows[0];
        if (!otpRow || otpRow.code !== code || Number(otpRow.expires_at) < Date.now()) {
          return jsonResponse({ error: 'Kode verifikasi salah atau sudah kedaluwarsa!' }, 400);
        }

        const userCheck = await queryNeon(env.DATABASE_URL, 'SELECT id FROM users WHERE email = $1', [email]);
        if (userCheck.rows.length === 0) {
          return jsonResponse({ error: 'Email tidak ditemukan di database.' }, 404);
        }

        await queryNeon(env.DATABASE_URL, 'UPDATE users SET password = $1 WHERE email = $2', [newPassword, email]);
        await queryNeon(env.DATABASE_URL, 'DELETE FROM password_reset_otps WHERE email = $1', [email]);

        return jsonResponse({ message: 'Password berhasil diubah! Mengarahkan ke halaman login...' });
      } catch (err) {
        console.error('Forgot password error:', err);
        return jsonResponse({ error: 'Terjadi kesalahan pada server.' }, 500);
      }
    }

    // Save / Update Quiz Score
    if (request.method === 'POST' && path === '/api/save-score') {
      try {
        const { email, score } = await request.json();
        if (!email) {
          return jsonResponse({ error: 'Email tidak valid.' }, 400);
        }

        const safeScore = Math.max(0, Number(score) || 0);
        const updated = await queryNeon(
          env.DATABASE_URL,
          'UPDATE users SET quiz_score = GREATEST(COALESCE(quiz_score, 0), $1) WHERE email = $2 RETURNING quiz_score',
          [safeScore, email]
        );

        return jsonResponse({
          success: true,
          message: 'Skor berhasil disimpan ke database!',
          quiz_score: updated.rows[0]?.quiz_score ?? safeScore
        });
      } catch (err) {
        console.error('Save score error:', err);
        return jsonResponse({ error: 'Terjadi kesalahan pada server saat menyimpan skor.' }, 500);
      }
    }

    // Get User Score
    if (request.method === 'GET' && path === '/api/get-score') {
      try {
        const email = url.searchParams.get('email');
        const result = await queryNeon(env.DATABASE_URL, 'SELECT quiz_score FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
          return jsonResponse({ success: true, quiz_score: result.rows[0].quiz_score || 0 });
        }
        return jsonResponse({ error: 'User tidak ditemukan.' }, 404);
      } catch (err) {
        console.error('Get score error:', err);
        return jsonResponse({ error: 'Kesalahan server.' }, 500);
      }
    }

    // Update Avatar
    if (request.method === 'POST' && path === '/api/update-avatar') {
      try {
        const { email, avatarUrl } = await request.json();
        if (!email || !avatarUrl) {
          return jsonResponse({ error: 'Email dan gambar profil wajib diisi.' }, 400);
        }

        const result = await queryNeon(
          env.DATABASE_URL,
          'UPDATE users SET avatar_url = $1 WHERE email = $2 RETURNING id, username, email, quiz_score, avatar_url',
          [avatarUrl, email]
        );

        if (result.rows.length === 0) {
          return jsonResponse({ error: 'User tidak ditemukan.' }, 404);
        }

        return jsonResponse({
          success: true,
          message: 'Foto profil berhasil diperbarui!',
          user: result.rows[0]
        });
      } catch (err) {
        console.error('Update avatar error:', err);
        return jsonResponse({ error: 'Gagal menyimpan foto profil.' }, 500);
      }
    }

    // Get Profile
    if (request.method === 'GET' && path === '/api/get-profile') {
      try {
        const email = url.searchParams.get('email');
        if (!email) {
          return jsonResponse({ error: 'Email tidak valid.' }, 400);
        }

        const result = await queryNeon(
          env.DATABASE_URL,
          'SELECT id, username, email, quiz_score, avatar_url FROM users WHERE email = $1',
          [email]
        );

        if (result.rows.length > 0) {
          return jsonResponse({ success: true, user: result.rows[0] });
        }
        return jsonResponse({ error: 'User tidak ditemukan.' }, 404);
      } catch (err) {
        console.error('Get profile error:', err);
        return jsonResponse({ error: 'Kesalahan server.' }, 500);
      }
    }

    // Fallback ke aset statis Cloudflare Pages jika path bukan /api/*
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return jsonResponse({ error: 'Endpoint tidak ditemukan.' }, 404);
  }
};

function corsHeaders(request) {
  const allowedOrigins = [
    'https://pjbl-antinarkoba-g8.pages.dev',
    'https://pjbl-antinarkoba8.pages.dev'
  ];
  const origin = request?.headers?.get('Origin') || '';
  const allowOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders()
    }
  });
}

// Eksekusi query ke Neon PostgreSQL HTTP SQL endpoint
async function queryNeon(databaseUrl, query, params = []) {
  if (!databaseUrl) {
    throw new Error('DATABASE_URL belum dikonfigurasi.');
  }

  const parsed = new URL(databaseUrl);
  const endpoint = `https://${parsed.hostname}/sql`;

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Neon-Connection-String': databaseUrl
    },
    body: JSON.stringify({ query, params })
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Neon SQL error (${response.status}): ${errText}`);
  }

  const data = await response.json();
  return {
    rows: Array.isArray(data.rows) ? data.rows : []
  };
}

async function ensureOtpTable(databaseUrl) {
  await queryNeon(
    databaseUrl,
    `CREATE TABLE IF NOT EXISTS password_reset_otps (
      email TEXT PRIMARY KEY,
      code TEXT NOT NULL,
      expires_at BIGINT NOT NULL
    )`
  );
}

async function sendOtpEmail(env, toEmail, code) {
  if (!env.RESEND_API_KEY) {
    throw new Error('RESEND_API_KEY belum diset.');
  }

  const fromAddress = env.EMAIL_FROM || 'onboarding@resend.dev';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: fromAddress,
      to: [toEmail],
      subject: 'Kode Verifikasi Reset Password - Edukasi Anti Narkoba',
      text: `Halo, kode verifikasi untuk mereset password akun kamu adalah: ${code}. Berlaku 10 menit. Jangan berikan kode ini kepada siapa pun.`
    })
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend error: ${body}`);
  }
}
