# 🔓 Broken Access Control (BAC) Lab

A hands-on bug bounty lab for practicing Broken Access Control vulnerabilities. Learn to identify and exploit common access control issues.


## 🚀 Quick Start

### Installation (3 Steps)

1. **Install Python 3.7+** (check: `python3 --version`)

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the lab:**
```bash
python3 app.py
```

Access at: `http://127.0.0.1:5000`

**Default Credentials:**
- Admin: `admin` / `admin123`
- User: `user1` / `user123`

## 🎯 Challenge Objectives

Find and exploit **2 vulnerabilities**:

### 🐛 Bug #1: Hidden Admin API Endpoints
1. Intercept admin's network traffic (Burp Suite or DevTools)
2. Discover hidden API endpoint paths from admin's requests
3. Access these endpoints as a regular user:
   - `/api/admin/settings` - Get admin settings and flags
   - `/api/admin/keys` - Get organization API keys
   - `/api/admin/users/all` - Get all users' sensitive data

### 🐛 Bug #2: Payment Bypass (Client-Side Security)
1. Intercept `/api/user/paid-status` API response
2. Change `"paid": false` to `"paid": true`
3. Unlock premium course videos without paying

## 🔍 Tools Needed

- **Burp Suite** (recommended) or **Browser DevTools**
- Intercept admin requests to discover endpoints
- Modify API responses to bypass restrictions

## 🎓 Solutions

<details>
<summary>Click to reveal solutions</summary>

### Solution #1: Hidden Admin API Endpoints
1. Set up Burp Suite or open DevTools (F12) → Network tab
2. Login as admin: `admin` / `admin123`
3. Visit `/admin` panel - it automatically makes API calls
4. See these requests: `/api/admin/settings`, `/api/admin/keys`, `/api/admin/users/all`
5. Login as regular user (`user1` / `user123`)
6. Access the discovered endpoints directly - they work because they only check authentication, not admin role!

### Solution #2: Payment Bypass
1. Login as regular user: `user1` / `user123`
2. Visit `/course` page
3. Intercept `/api/user/paid-status` request (Burp Suite or DevTools)
4. Modify response: `{"paid": false}` → `{"paid": true}`
5. Refresh page - premium videos unlocked!

</details>

## 📋 Flags to Find

- `BAC_LAB_USER_DATA` - Found in your own user data
- `BAC_LAB_ADMIN_PANEL_ACCESSED` - Found in admin settings
- `ADMIN_API_KEY_2024_SECRET` - Found in admin API keys
- Organization API Keys: `ORG_ALPHA_API_KEY_XYZ123`, `ORG_BETA_API_KEY_ABC456`, etc.

## 📚 Resources

- **Bug Bounty Course:** [lureo.shop](https://lureo.shop)

## 📱 Connect

- **GitHub:** [](https://github.com/)

## ⚠️ Disclaimer

This lab is for **EDUCATIONAL PURPOSES ONLY**. Use responsibly and only on systems you own or have explicit permission to test.


**Happy Hacking! 🎉**
