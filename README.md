# Product Requirements Document: *Star-Forge Notes*

## 1. Executive Summary
**Star-Forge Notes** is a self-hosted, lightweight personal knowledge management system. It replaces the flat "post-it" style of Google Keep with a deep-nesting tree structure. Designed for restricted shared hosting, it uses **PHP + JSON + Markdown**, eliminating the need for MySQL, Node.js, or Docker.

## 2. Core Objectives
- **Hierarchical Organization**: Infinite nesting of notes in a sidebar tree.
- **Database-Free (Flat-File)**: All data is stored in human-readable `.md` and `.json` files.
- **Multi-User & Admin Control**: Restricted access with an approval-based registration system.
- **Discovery**: Robust search and cross-folder tagging system.

## 3. Technical Requirements
### 3.1 Stack
- **Backend**: PHP 8.1+ (File System API for CRUD).
- **Storage Architecture**:
    - `/data/users.json`: Registry of user credentials, status (pending/active), and roles.
    - `/vaults/{user_id}/`: Isolated folder containing a user's `.md` files and `structure.json`.
- **Frontend**: Vanilla JS, CSS3 (Tailwind CSS via CDN).
- **Editor**: Vditor (WYSIWYG Markdown editor).

### 3.2 Constraints
- Zero database dependencies (No MySQL/MariaDB/SQLite).
- Compatible with standard Apache/Litespeed shared hosting.

## 4. Feature Requirements

### 4.1 Layout & Navigation
- **The Tree View**: Sidebar mirroring the physical folder structure.
- **User Workspace**: Resizable split-pane for editing and previewing.
- **Admin Panel**: A dedicated "hidden" route for administrators to:
    - Review "Free Account" requests.
    - Enable/Disable/Delete users.
    - Audit disk usage (vault sizes).

### 4.2 Content & Search
- **Full-Text Search**: PHP-powered recursive scan of all .md files within the user's specific vault.
    - Support for `In this folder` or `Global` scopes.
- **Tagging System**: Support for `#tags` within Markdown frontmatter.
    - **Tag Cloud/Sidebar**: A dedicated section to filter notes by tags regardless of their folder location.
- **Auto-Save**: JS-driven asynchronous saves to the server.

### 4.3 User System (The "Gatekeeper")
- Registration Flow:
    1. User fills out a "Request Account" form.
    2. Account is created with a status: "pending" flag in users.json.
    3. User cannot log in until Admin changes status to "active".
- **Isolation**: Users can never navigate outside their assigned /vaults/{user_id}/ directory.

### 4.4 AI Integration (FUTURE)
- **API-based**: Simple input fields for OpenAI or Anthropic API keys.
- **Contextual Actions**: Summarization and tag suggestions based on active note content.

## 5. Security & Privacy
- **Directory Protection**: `.htaccess` placed in `/vaults/` and `/data/` to prevent direct browser access to files.
- **Session Management**: Secure PHP sessions with `HttpOnly` and `SameSite` flags.
- **Admin Shield**: Only users with `role: "admin"` in `users.json` can access the management dashboard.

## 6. Development Phases
- **Phase 1 (User Engine)**: Build the users.json logic, registration form, and login system.
- **Phase 2 (The Vault)**: Develop the PHP File Manager to handle directory creation/deletion per user.
- **Phase 3 (Admin Tools)**: Create the dashboard for approving/managing users.
- **Phase 4 (Search & Tags)**: Implement the recursive file scanner and tag parser.
- **Phase 5 (The Editor)**: Integrate Vditor and finalize the UI layout.

## 7. First Draft (Implemented)
This repository now includes a first-draft implementation based on the requirements above.

### Included
- PHP flat-file auth with `users.json` (`pending` / `active` / `disabled`)
- Request-account flow and login/logout
- Per-user vault directories under `/vaults/{user_id}/`
- Markdown note create/load/save with `structure.json` indexing
- Basic tree list, full-text search (global/folder), and tag cloud from frontmatter
- Admin panel for approve/disable/delete user accounts and vault size audit
- Tailwind-based UI and Vditor integration (CDN)
- `.htaccess` protections in `/data` and `/vaults`

### Project Structure
- `/public/index.php` — app entrypoint and UI
- `/src/app.php` — storage, auth, vault, search, and tag logic
- `/data/users.json` — user registry
- `/vaults/` — per-user markdown vault storage

### Local Run
Use PHP's built-in web server from repository root:

```bash
php -S 127.0.0.1:8080 -t public
```

Then open:
- `http://127.0.0.1:8080/?route=login`

### Draft Admin Access
For initial testing:
- Username: `admin`
- Password: `admin123!`

Change this credential in `data/users.json` before any real deployment.
