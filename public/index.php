<?php

declare(strict_types=1);

require __DIR__ . '/../src/app.php';
app_bootstrap();

$route = $_GET['route'] ?? 'app';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$message = null;
$error = null;
$csrfToken = csrf_token();

if ($route === 'logout') {
    session_destroy();
    header('Location: ?route=login');
    exit;
}

if ($route === 'login' && $method === 'POST') {
    try {
        verify_csrf($_POST['csrf'] ?? null);
        $error = login_user($_POST['username'] ?? '', $_POST['password'] ?? '');
        if ($error === null) {
            header('Location: ?route=' . (is_password_change_required() ? 'change-password' : 'app'));
            exit;
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

if ($route === 'change-password' && $method === 'POST') {
    require_auth();
    try {
        verify_csrf($_POST['csrf'] ?? null);
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if (strlen($newPassword) < MIN_PASSWORD_LENGTH) {
            throw new RuntimeException('New password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.');
        }
        if ($newPassword !== $confirmPassword) {
            throw new RuntimeException('New password and confirmation do not match.');
        }

        $activeUser = current_user();
        $record = $activeUser ? find_user_by_id($activeUser['id']) : null;
        if (!$record || !password_verify($currentPassword, $record['password_hash'] ?? '')) {
            throw new RuntimeException('Current password is incorrect.');
        }
        if (!set_user_password($record['id'], $newPassword, false)) {
            throw new RuntimeException('Unable to update password.');
        }

        $updatedRecord = find_user_by_id($record['id']);
        if ($updatedRecord) {
            set_session_user($updatedRecord);
        }
        $message = 'Password updated.';
        $route = 'app';
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

if ($route === 'register' && $method === 'POST') {
    try {
        verify_csrf($_POST['csrf'] ?? null);
        $error = request_account($_POST['username'] ?? '', $_POST['password'] ?? '');
        if ($error === null) {
            $message = 'Account requested. Wait for admin approval.';
            $route = 'login';
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

if ($route === 'admin-action' && $method === 'POST') {
    require_admin();
    try {
        verify_csrf($_POST['csrf'] ?? null);
    } catch (Throwable $e) {
        header('Location: ?route=admin&msg=' . urlencode($e->getMessage()));
        exit;
    }

    $users = read_users();
    $userId = trim($_POST['user_id'] ?? '');
    $action = trim($_POST['action'] ?? '');
    $defaultPassword = trim($_POST['default_password'] ?? '');
    $adminActionError = null;

    foreach ($users as &$u) {
        if (($u['id'] ?? '') !== $userId || $u['id'] === 'admin') {
            continue;
        }

        if ($action === 'approve') {
            $u['status'] = 'active';
            $message = "Approved {$u['username']}";
        } elseif ($action === 'disable') {
            $u['status'] = 'disabled';
            $message = "Disabled {$u['username']}";
        } elseif ($action === 'delete') {
            $u['__delete'] = true;
            $message = "Deleted {$u['username']}";
        } elseif ($action === 'reset-password') {
            if (strlen($defaultPassword) < MIN_PASSWORD_LENGTH) {
                $adminActionError = 'Default password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.';
            } else {
                $u['password_hash'] = password_hash($defaultPassword, PASSWORD_DEFAULT);
                $u['force_password_change'] = true;
                $u['status'] = 'active';
                $message = "Password reset for {$u['username']}";
            }
        }
        break;
    }
    unset($u);

    if ($adminActionError === null) {
        $users = array_values(array_filter($users, static fn($u) => !isset($u['__delete'])));
        write_users($users);
    }

    if ($action === 'delete' && $userId !== '') {
        $vault = user_vault_path($userId);
        if (is_dir($vault)) {
            $iter = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($vault, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iter as $item) {
                $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
            }
            rmdir($vault);
        }
    }

    header('Location: ?route=admin&msg=' . urlencode($adminActionError ?? $message ?? 'Updated'));
    exit;
}

if ($route === 'api' && $method === 'POST') {
    require_auth();
    header('Content-Type: application/json');

    $user = current_user();
    $action = $_POST['action'] ?? '';

    try {
        verify_csrf($_POST['csrf'] ?? null);

        if ($action === 'create') {
            $err = create_note($user['id'], $_POST['path'] ?? '');
            if ($err) {
                echo json_encode(['ok' => false, 'error' => $err]);
            } else {
                echo json_encode(['ok' => true, 'structure' => get_structure($user['id'])]);
            }
            exit;
        }

        if ($action === 'save') {
            $err = save_note($user['id'], $_POST['path'] ?? '', $_POST['content'] ?? '');
            echo json_encode(['ok' => $err === null, 'error' => $err]);
            exit;
        }

        if ($action === 'load') {
            $content = read_note($user['id'], $_POST['path'] ?? '');
            echo json_encode(['ok' => $content !== null, 'content' => $content]);
            exit;
        }

        if ($action === 'search') {
            $results = search_notes($user['id'], $_POST['query'] ?? '', $_POST['scope'] ?? 'global', $_POST['folder'] ?? '');
            echo json_encode(['ok' => true, 'results' => $results]);
            exit;
        }

        if ($action === 'tags') {
            echo json_encode(['ok' => true, 'tags' => all_tags($user['id'])]);
            exit;
        }

        echo json_encode(['ok' => false, 'error' => 'Unknown action']);
    } catch (Throwable $e) {
        echo json_encode(['ok' => false, 'error' => $e->getMessage()]);
    }
    exit;
}

$user = current_user();

if (!$user && !in_array($route, ['login', 'register'], true)) {
    header('Location: ?route=login');
    exit;
}

if ($user && ($user['force_password_change'] ?? false) && !in_array($route, ['change-password', 'logout'], true)) {
    header('Location: ?route=change-password');
    exit;
}

if ($route === 'admin') {
    require_admin();
}

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Star-Forge Notes</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://unpkg.com/vditor/dist/index.css" />
    <script>
        (() => {
            const config = {
                defaultTheme: 'light-slate',
                themes: [
                    'light-slate', 'light-sand', 'light-mint', 'light-lavender', 'light-sky',
                    'dark-slate', 'dark-graphite', 'dark-forest', 'dark-plum', 'dark-ocean',
                ],
            };
            const allowedThemes = new Set(config.themes);
            window.sfThemeConfig = config;
            window.sfApplyTheme = (theme, persist = true) => {
                const isValidTheme = allowedThemes.has(theme);
                const selectedTheme = isValidTheme ? theme : config.defaultTheme;
                if (!isValidTheme) {
                    console.warn('Invalid theme provided, using default:', theme, '->', config.defaultTheme);
                }
                document.documentElement.setAttribute('data-theme', selectedTheme);
                if (persist) localStorage.setItem('sf-theme', selectedTheme);
                return selectedTheme;
            };
            const savedTheme = localStorage.getItem('sf-theme') || config.defaultTheme;
            window.sfApplyTheme(savedTheme, false);
        })();
    </script>
    <style>
        :root {
            --sf-bg: #f1f5f9;
            --sf-panel: #ffffff;
            --sf-text: #0f172a;
            --sf-muted: #475569;
            --sf-border: #cbd5e1;
            --sf-input-bg: #ffffff;
            --sf-tag-bg: #e2e8f0;
            --sf-tag-text: #0f172a;
            --sf-link: #4338ca;
            color-scheme: light;
        }
        :root[data-theme="light-slate"] {
            --sf-bg: #f1f5f9; --sf-panel: #ffffff; --sf-text: #0f172a; --sf-muted: #475569; --sf-border: #cbd5e1;
            --sf-input-bg: #ffffff; --sf-tag-bg: #e2e8f0; --sf-tag-text: #0f172a; --sf-link: #4338ca; color-scheme: light;
        }
        :root[data-theme="light-sand"] {
            --sf-bg: #f8f5ef; --sf-panel: #fffdf8; --sf-text: #2f2315; --sf-muted: #6f5b44; --sf-border: #dfd3c0;
            --sf-input-bg: #fffaf0; --sf-tag-bg: #eadfce; --sf-tag-text: #2f2315; --sf-link: #92400e; color-scheme: light;
        }
        :root[data-theme="light-mint"] {
            --sf-bg: #ecfdf5; --sf-panel: #f8fffb; --sf-text: #064e3b; --sf-muted: #065f46; --sf-border: #a7f3d0;
            --sf-input-bg: #ffffff; --sf-tag-bg: #d1fae5; --sf-tag-text: #064e3b; --sf-link: #0f766e; color-scheme: light;
        }
        :root[data-theme="light-lavender"] {
            --sf-bg: #f5f3ff; --sf-panel: #fcfcff; --sf-text: #312e81; --sf-muted: #5b5aa0; --sf-border: #c4b5fd;
            --sf-input-bg: #ffffff; --sf-tag-bg: #e9e5ff; --sf-tag-text: #312e81; --sf-link: #6d28d9; color-scheme: light;
        }
        :root[data-theme="light-sky"] {
            --sf-bg: #f0f9ff; --sf-panel: #ffffff; --sf-text: #0c4a6e; --sf-muted: #0369a1; --sf-border: #bae6fd;
            --sf-input-bg: #ffffff; --sf-tag-bg: #dbeafe; --sf-tag-text: #0c4a6e; --sf-link: #1d4ed8; color-scheme: light;
        }
        :root[data-theme="dark-slate"] {
            --sf-bg: #0f172a; --sf-panel: #1e293b; --sf-text: #e2e8f0; --sf-muted: #94a3b8; --sf-border: #475569;
            --sf-input-bg: #0f172a; --sf-tag-bg: #334155; --sf-tag-text: #e2e8f0; --sf-link: #93c5fd; color-scheme: dark;
        }
        :root[data-theme="dark-graphite"] {
            --sf-bg: #111827; --sf-panel: #1f2937; --sf-text: #f3f4f6; --sf-muted: #9ca3af; --sf-border: #4b5563;
            --sf-input-bg: #111827; --sf-tag-bg: #374151; --sf-tag-text: #f3f4f6; --sf-link: #a5b4fc; color-scheme: dark;
        }
        :root[data-theme="dark-forest"] {
            --sf-bg: #052e16; --sf-panel: #14532d; --sf-text: #dcfce7; --sf-muted: #86efac; --sf-border: #15803d;
            --sf-input-bg: #052e16; --sf-tag-bg: #166534; --sf-tag-text: #dcfce7; --sf-link: #5eead4; color-scheme: dark;
        }
        :root[data-theme="dark-plum"] {
            --sf-bg: #2e1065; --sf-panel: #3b0764; --sf-text: #f5d0fe; --sf-muted: #e879f9; --sf-border: #a855f7;
            --sf-input-bg: #2e1065; --sf-tag-bg: #581c87; --sf-tag-text: #f5d0fe; --sf-link: #c4b5fd; color-scheme: dark;
        }
        :root[data-theme="dark-ocean"] {
            --sf-bg: #082f49; --sf-panel: #0c4a6e; --sf-text: #e0f2fe; --sf-muted: #7dd3fc; --sf-border: #0284c7;
            --sf-input-bg: #082f49; --sf-tag-bg: #075985; --sf-tag-text: #e0f2fe; --sf-link: #93c5fd; color-scheme: dark;
        }
        body.theme-page { background: var(--sf-bg); color: var(--sf-text); }
        .theme-container { --sf-shell-padding: 20px; min-height: 100vh; padding: var(--sf-shell-padding); }
        .theme-panel { background: var(--sf-panel); color: var(--sf-text); border: 1px solid var(--sf-border); }
        .theme-input { background: var(--sf-input-bg); color: var(--sf-text); border-color: var(--sf-border); }
        .theme-muted { color: var(--sf-muted); }
        .theme-tag { background: var(--sf-tag-bg); color: var(--sf-tag-text); }
        .theme-link { color: var(--sf-link); }
        .tree-root, .tree-branch { list-style: none; margin: 0; padding-left: 0; }
        .tree-item { margin: 2px 0; }
        .tree-folder { margin: 0; }
        .tree-folder > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 6px; padding: 2px 4px; border-radius: 4px; }
        .tree-folder > summary::-webkit-details-marker { display: none; }
        .tree-caret { width: 10px; color: var(--sf-muted); font-size: 11px; text-align: center; }
        .tree-folder[open] > summary .tree-caret::before { content: "▾"; }
        .tree-folder:not([open]) > summary .tree-caret::before { content: "▸"; }
        .tree-folder-icon, .tree-file-icon { color: var(--sf-muted); width: 14px; text-align: center; }
        .tree-branch { margin-left: 8px; padding-left: 10px; border-left: 1px solid var(--sf-border); }
        .tree-note-button { display: inline-flex; align-items: center; gap: 6px; width: 100%; text-align: left; border-radius: 4px; padding: 2px 4px; }
        .tree-note-button:hover, .tree-folder > summary:hover { background: color-mix(in srgb, var(--sf-tag-bg) 55%, transparent); }
        .tree-note-button.is-active { background: color-mix(in srgb, var(--sf-tag-bg) 85%, transparent); font-weight: 600; }
        #vditor { min-height: 60vh; }
    </style>
</head>
<body class="theme-page min-h-screen">
<div class="theme-container w-full">
    <header class="mb-4 flex items-center justify-between">
        <h1 class="text-2xl font-bold">Star-Forge Notes (Draft)</h1>
        <div class="flex gap-2 items-center flex-wrap justify-end">
            <label class="text-sm theme-muted" for="themeSelect">Theme</label>
            <select id="themeSelect" class="theme-input border rounded px-2 py-1 text-sm">
                <optgroup label="Light Themes">
                    <option value="light-slate">Light Slate</option>
                    <option value="light-sand">Light Sand</option>
                    <option value="light-mint">Light Mint</option>
                    <option value="light-lavender">Light Lavender</option>
                    <option value="light-sky">Light Sky</option>
                </optgroup>
                <optgroup label="Dark Themes">
                    <option value="dark-slate">Dark Slate</option>
                    <option value="dark-graphite">Dark Graphite</option>
                    <option value="dark-forest">Dark Forest</option>
                    <option value="dark-plum">Dark Plum</option>
                    <option value="dark-ocean">Dark Ocean</option>
                </optgroup>
            </select>
            <?php if ($user): ?>
                <span class="text-sm theme-muted">Hi, <?= htmlspecialchars($user['username']) ?></span>
                <?php if (($user['role'] ?? 'user') === 'admin'): ?><a class="px-3 py-1 bg-violet-600 text-white rounded" href="?route=admin">Admin</a><?php endif; ?>
                <a class="px-3 py-1 bg-slate-700 text-white rounded" href="?route=logout">Logout</a>
            <?php endif; ?>
        </div>
    </header>

    <?php if ($message): ?><div class="mb-3 p-2 bg-emerald-100 border border-emerald-300 rounded"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="mb-3 p-2 bg-rose-100 border border-rose-300 rounded"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($route === 'login' || $route === 'register'): ?>
        <div class="max-w-md mx-auto theme-panel rounded shadow p-4">
            <?php if ($route === 'login'): ?>
                <h2 class="text-xl font-semibold mb-3">Login</h2>
                <form method="post" action="?route=login" class="space-y-2">
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input class="theme-input w-full border rounded p-2" name="username" placeholder="Username" required>
                    <input class="theme-input w-full border rounded p-2" type="password" name="password" placeholder="Password" required>
                    <button class="w-full bg-indigo-600 text-white rounded p-2">Login</button>
                </form>
                <p class="text-sm mt-2">No account? <a class="theme-link" href="?route=register">Request Account</a></p>
                <p class="text-xs text-amber-700 mt-3">Draft mode warning: rotate any seed credentials before deployment.</p>
            <?php else: ?>
                <h2 class="text-xl font-semibold mb-3">Request Account</h2>
                <form method="post" action="?route=register" class="space-y-2">
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                    <input class="theme-input w-full border rounded p-2" name="username" placeholder="Username" required>
                    <input class="theme-input w-full border rounded p-2" type="password" name="password" placeholder="Password" required>
                    <button class="w-full bg-indigo-600 text-white rounded p-2">Submit Request</button>
                </form>
                <p class="text-sm mt-2"><a class="theme-link" href="?route=login">Back to Login</a></p>
            <?php endif; ?>
        </div>
    <?php elseif ($route === 'change-password'): ?>
        <div class="max-w-md mx-auto theme-panel rounded shadow p-4">
            <h2 class="text-xl font-semibold mb-3">Change Password</h2>
            <p class="text-sm text-amber-700 mb-3">You must set a new password before continuing.</p>
            <form method="post" action="?route=change-password" class="space-y-2">
                <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                <input class="theme-input w-full border rounded p-2" type="password" name="current_password" placeholder="Current Password" aria-label="Current password" required>
                <input class="theme-input w-full border rounded p-2" type="password" name="new_password" placeholder="New Password (<?= MIN_PASSWORD_LENGTH ?>+ chars)" aria-label="New password" required>
                <input class="theme-input w-full border rounded p-2" type="password" name="confirm_password" placeholder="Confirm New Password" aria-label="Confirm new password" required>
                <button class="w-full bg-indigo-600 text-white rounded p-2">Update Password</button>
            </form>
        </div>

    <?php elseif ($route === 'admin'): ?>
        <?php $adminMsg = $_GET['msg'] ?? null; if ($adminMsg): ?><div class="mb-3 p-2 bg-indigo-100 border border-indigo-300 rounded"><?= htmlspecialchars($adminMsg) ?></div><?php endif; ?>
        <?php $users = read_users(); ?>
        <div class="theme-panel rounded shadow p-4">
            <h2 class="text-xl font-semibold mb-3">Admin Panel</h2>
            <div class="overflow-auto">
                <table class="w-full text-sm">
                    <thead><tr class="text-left border-b"><th class="p-2">User</th><th class="p-2">Status</th><th class="p-2">Role</th><th class="p-2">Vault Size</th><th class="p-2">Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($users as $u): ?>
                        <tr class="border-b">
                            <td class="p-2"><?= htmlspecialchars($u['username']) ?></td>
                            <td class="p-2"><?= htmlspecialchars($u['status'] ?? 'pending') ?></td>
                            <td class="p-2"><?= htmlspecialchars($u['role'] ?? 'user') ?></td>
                            <td class="p-2"><?= htmlspecialchars(format_bytes(folder_size_bytes(user_vault_path($u['id'])))) ?></td>
                            <td class="p-2">
                                <?php if (($u['id'] ?? '') !== 'admin'): ?>
                                <form method="post" action="?route=admin-action" class="inline-flex gap-1">
                                    <input type="hidden" name="user_id" value="<?= htmlspecialchars($u['id']) ?>">
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                                    <button class="px-2 py-1 bg-emerald-600 text-white rounded" name="action" value="approve" type="submit">Approve</button>
                                    <button class="px-2 py-1 bg-amber-600 text-white rounded" name="action" value="disable" type="submit">Disable</button>
                                    <button class="px-2 py-1 bg-rose-600 text-white rounded" name="action" value="delete" type="submit" onclick="return confirm('Delete user and vault?')">Delete</button>
                                </form>
                                <form method="post" action="?route=admin-action" class="inline-flex gap-1 mt-1">
                                    <input type="hidden" name="user_id" value="<?= htmlspecialchars($u['id']) ?>">
                                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrfToken) ?>">
                                    <input class="theme-input border rounded px-2 py-1" type="password" name="default_password" placeholder="Default password" aria-label="Default reset password" required>
                                    <button class="px-2 py-1 bg-indigo-600 text-white rounded" name="action" value="reset-password" type="submit">Reset Password</button>
                                </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

    <?php else: ?>
        <?php
            require_auth();
            $structure = get_structure($user['id']);
            $files = $structure['files'] ?? [];
        ?>
        <div class="grid grid-cols-12 gap-4">
            <aside class="col-span-12 md:col-span-3 theme-panel rounded shadow p-3">
                <h3 class="font-semibold mb-2">Tree</h3>
                <ul id="tree" class="tree-root text-sm max-h-[45vh] overflow-auto"></ul>
                <div class="mt-3 space-y-1">
                    <input id="newPath" class="theme-input w-full border rounded p-2 text-sm" placeholder="folder/my-note.md">
                    <button id="createBtn" class="w-full bg-indigo-600 text-white rounded p-2 text-sm">Create Note</button>
                </div>
                <div class="mt-3">
                    <h4 class="font-semibold mb-1">Tags</h4>
                    <div id="tags" class="flex flex-wrap gap-1 text-xs"></div>
                </div>
            </aside>
            <main class="col-span-12 md:col-span-9 theme-panel rounded shadow p-3">
                <div class="flex flex-wrap gap-2 items-center mb-2">
                    <input id="searchQuery" class="theme-input border rounded p-2 text-sm flex-1" placeholder="Search notes...">
                    <select id="scope" class="theme-input border rounded p-2 text-sm"><option value="global">Global</option><option value="folder">In this folder</option></select>
                    <input id="scopeFolder" class="theme-input border rounded p-2 text-sm" placeholder="folder path (optional)">
                    <button id="searchBtn" class="bg-slate-700 text-white rounded px-3 py-2 text-sm">Search</button>
                    <span id="activeNote" class="text-sm theme-muted"></span>
                </div>
                <div id="searchResults" class="text-sm mb-2"></div>
                <div id="vditor"></div>
                <textarea id="fallbackEditor" class="theme-input w-full min-h-[60vh] border rounded p-2 hidden"></textarea>
                <button id="saveBtn" class="mt-2 bg-emerald-600 text-white rounded px-3 py-2 text-sm">Save Now</button>
            </main>
        </div>
        <script id="tree-files-data" type="application/json"><?= json_encode($files, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
        <script src="https://unpkg.com/vditor/dist/index.min.js"></script>
        <script>
            const state = { activeNote: '', editor: null, autosaveTimer: null };
            const csrfToken = <?= json_encode($csrfToken) ?>;
            const treeFiles = JSON.parse(document.getElementById('tree-files-data')?.textContent || '[]');

            async function api(payload) {
                const body = new URLSearchParams({ ...payload, csrf: csrfToken });
                const res = await fetch('?route=api', { method: 'POST', body });
                return res.json();
            }

            function contentGet() {
                if (state.editor) return state.editor.getValue();
                return document.getElementById('fallbackEditor').value;
            }

            function contentSet(value) {
                if (state.editor) state.editor.setValue(value || '');
                else document.getElementById('fallbackEditor').value = value || '';
            }

            function buildTree(paths) {
                const root = { folders: new Map(), files: [] };
                paths.forEach((path) => {
                    const parts = path.split('/').filter(Boolean);
                    if (!parts.length) return;
                    let node = root;
                    parts.forEach((part, index) => {
                        const isFile = index === parts.length - 1;
                        if (isFile) {
                            node.files.push({ name: part, path });
                            return;
                        }
                        if (!node.folders.has(part)) {
                            node.folders.set(part, { folders: new Map(), files: [] });
                        }
                        node = node.folders.get(part);
                    });
                });
                return root;
            }

            function caseInsensitiveCompare(left, right) {
                return left.localeCompare(right, 'en', { sensitivity: 'base' });
            }

            function renderTreeNode(node, container) {
                Array.from(node.folders.entries())
                    .sort(([a], [b]) => caseInsensitiveCompare(a, b))
                    .forEach(([folderName, folderNode]) => {
                        const item = document.createElement('li');
                        item.className = 'tree-item';

                        const details = document.createElement('details');
                        details.className = 'tree-folder';
                        details.open = true;

                        const summary = document.createElement('summary');
                        const caret = document.createElement('span');
                        caret.className = 'tree-caret';
                        const folderIcon = document.createElement('span');
                        folderIcon.className = 'tree-folder-icon';
                        folderIcon.textContent = '📁';
                        const label = document.createElement('span');
                        label.textContent = folderName;
                        summary.append(caret, folderIcon, label);
                        details.appendChild(summary);

                        const branch = document.createElement('ul');
                        branch.className = 'tree-branch';
                        renderTreeNode(folderNode, branch);
                        details.appendChild(branch);
                        item.appendChild(details);
                        container.appendChild(item);
                    });

                node.files
                    .sort((a, b) => caseInsensitiveCompare(a.name, b.name))
                    .forEach((file) => {
                        const item = document.createElement('li');
                        item.className = 'tree-item';

                        const btn = document.createElement('button');
                        btn.className = 'tree-note-button';
                        btn.dataset.note = file.path;

                        const fileIcon = document.createElement('span');
                        fileIcon.className = 'tree-file-icon';
                        fileIcon.textContent = '📄';

                        const label = document.createElement('span');
                        label.textContent = file.name;
                        btn.append(fileIcon, label);

                        item.appendChild(btn);
                        container.appendChild(item);
                    });
            }

            function renderTree(paths) {
                const tree = document.getElementById('tree');
                tree.innerHTML = '';
                if (!paths.length) {
                    const empty = document.createElement('li');
                    empty.className = 'theme-muted';
                    empty.textContent = 'No notes yet.';
                    tree.appendChild(empty);
                    return;
                }
                const root = buildTree(paths);
                renderTreeNode(root, tree);
            }

            function highlightActiveTreeNote() {
                const buttons = document.querySelectorAll('#tree [data-note]');
                buttons.forEach((btn) => {
                    const active = btn.dataset.note === state.activeNote;
                    btn.classList.toggle('is-active', active);
                    if (active) {
                        let parent = btn.parentElement;
                        while (parent) {
                            if (parent.tagName === 'DETAILS') parent.open = true;
                            parent = parent.parentElement;
                        }
                    }
                });
            }

            async function loadTags() {
                const out = await api({ action: 'tags' });
                const el = document.getElementById('tags');
                el.innerHTML = '';
                if (!out.ok) return;
                Object.entries(out.tags).forEach(([tag, count]) => {
                    const btn = document.createElement('button');
                    btn.className = 'px-2 py-1 rounded theme-tag';
                    btn.textContent = `#${tag} (${count})`;
                    btn.onclick = () => {
                        document.getElementById('searchQuery').value = tag;
                        document.getElementById('searchBtn').click();
                    };
                    el.appendChild(btn);
                });
            }

            async function openNote(path) {
                state.activeNote = path;
                document.getElementById('activeNote').textContent = path;
                highlightActiveTreeNote();
                const out = await api({ action: 'load', path });
                contentSet(out.content || '');
            }

            async function saveCurrent() {
                if (!state.activeNote) return;
                await api({ action: 'save', path: state.activeNote, content: contentGet() });
            }

            function wireAutosave() {
                const target = state.editor ? state.editor.vditor.element : document.getElementById('fallbackEditor');
                target.addEventListener('input', () => {
                    clearTimeout(state.autosaveTimer);
                    state.autosaveTimer = setTimeout(saveCurrent, 1200);
                });
            }

            document.getElementById('tree').addEventListener('click', (event) => {
                const target = event.target.closest('button[data-note]');
                if (!target) return;
                openNote(target.dataset.note);
            });

            document.getElementById('createBtn').addEventListener('click', async () => {
                const path = document.getElementById('newPath').value.trim();
                if (!path) return;
                const out = await api({ action: 'create', path });
                if (!out.ok) return alert(out.error || 'Failed');
                location.reload();
            });

            document.getElementById('saveBtn').addEventListener('click', saveCurrent);

            document.getElementById('searchBtn').addEventListener('click', async () => {
                const out = await api({
                    action: 'search',
                    query: document.getElementById('searchQuery').value,
                    scope: document.getElementById('scope').value,
                    folder: document.getElementById('scopeFolder').value,
                });
                const el = document.getElementById('searchResults');
                el.innerHTML = '';
                (out.results || []).forEach((path) => {
                    const b = document.createElement('button');
                    b.className = 'mr-2 theme-link underline';
                    b.textContent = path;
                    b.onclick = () => openNote(path);
                    el.appendChild(b);
                });
            });

            (async () => {
                try {
                    if (window.Vditor) {
                        state.editor = new Vditor('vditor', {
                            height: 560,
                            mode: 'wysiwyg',
                            lang: 'en_US',
                            cache: { enable: false }
                        });
                    } else {
                        document.getElementById('vditor').classList.add('hidden');
                        document.getElementById('fallbackEditor').classList.remove('hidden');
                    }
                } catch (e) {
                    document.getElementById('vditor').classList.add('hidden');
                    document.getElementById('fallbackEditor').classList.remove('hidden');
                }
                renderTree(treeFiles);
                setTimeout(wireAutosave, 500);
                await loadTags();
            })();
        </script>
    <?php endif; ?>
</div>
<script>
    (() => {
        const config = window.sfThemeConfig;
        if (!config) {
            console.error('Theme configuration (window.sfThemeConfig) was not initialized. Ensure the theme initialization script runs before this code.');
            return;
        }
        if (!Array.isArray(config.themes)) {
            console.error('Theme configuration is invalid: themes must be an array, received:', typeof config.themes);
            return;
        }
        if (typeof config.defaultTheme !== 'string') {
            console.error('Theme configuration is invalid: defaultTheme must be a string.');
            return;
        }
        const themes = new Set(config.themes);
        const applyTheme = window.sfApplyTheme;
        if (typeof applyTheme !== 'function') return;

        const select = document.getElementById('themeSelect');
        if (!select) return;
        const currentTheme = document.documentElement.getAttribute('data-theme') || config.defaultTheme;
        select.value = themes.has(currentTheme) ? currentTheme : config.defaultTheme;
        select.addEventListener('change', (event) => applyTheme(event.target.value, true));
    })();
</script>
</body>
</html>
