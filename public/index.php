<?php

declare(strict_types=1);

require __DIR__ . '/../src/app.php';
app_bootstrap();

$route = $_GET['route'] ?? 'app';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$message = null;
$error = null;

if ($route === 'logout') {
    session_destroy();
    header('Location: ?route=login');
    exit;
}

if ($route === 'login' && $method === 'POST') {
    $error = login_user($_POST['username'] ?? '', $_POST['password'] ?? '');
    if ($error === null) {
        header('Location: ?route=app');
        exit;
    }
}

if ($route === 'register' && $method === 'POST') {
    $error = request_account($_POST['username'] ?? '', $_POST['password'] ?? '');
    if ($error === null) {
        $message = 'Account requested. Wait for admin approval.';
        $route = 'login';
    }
}

if ($route === 'admin-action' && $method === 'POST') {
    require_admin();
    $users = read_users();
    $userId = trim($_POST['user_id'] ?? '');
    $action = trim($_POST['action'] ?? '');

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
        }
    }
    unset($u);

    $users = array_values(array_filter($users, static fn($u) => !isset($u['__delete'])));
    write_users($users);

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

    header('Location: ?route=admin&msg=' . urlencode($message ?? 'Updated'));
    exit;
}

if ($route === 'api' && $method === 'POST') {
    require_auth();
    header('Content-Type: application/json');

    $user = current_user();
    $action = $_POST['action'] ?? '';

    try {
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
    <style>#vditor { min-height: 60vh; }</style>
</head>
<body class="bg-slate-100 text-slate-900">
<div class="max-w-7xl mx-auto p-4">
    <header class="mb-4 flex items-center justify-between">
        <h1 class="text-2xl font-bold">Star-Forge Notes (Draft)</h1>
        <?php if ($user): ?>
            <div class="flex gap-2 items-center">
                <span class="text-sm">Hi, <?= htmlspecialchars($user['username']) ?></span>
                <?php if (($user['role'] ?? 'user') === 'admin'): ?><a class="px-3 py-1 bg-violet-600 text-white rounded" href="?route=admin">Admin</a><?php endif; ?>
                <a class="px-3 py-1 bg-slate-700 text-white rounded" href="?route=logout">Logout</a>
            </div>
        <?php endif; ?>
    </header>

    <?php if ($message): ?><div class="mb-3 p-2 bg-emerald-100 border border-emerald-300 rounded"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="mb-3 p-2 bg-rose-100 border border-rose-300 rounded"><?= htmlspecialchars($error) ?></div><?php endif; ?>

    <?php if ($route === 'login' || $route === 'register'): ?>
        <div class="max-w-md mx-auto bg-white rounded shadow p-4">
            <?php if ($route === 'login'): ?>
                <h2 class="text-xl font-semibold mb-3">Login</h2>
                <form method="post" action="?route=login" class="space-y-2">
                    <input class="w-full border rounded p-2" name="username" placeholder="Username" required>
                    <input class="w-full border rounded p-2" type="password" name="password" placeholder="Password" required>
                    <button class="w-full bg-indigo-600 text-white rounded p-2">Login</button>
                </form>
                <p class="text-sm mt-2">No account? <a class="text-indigo-700" href="?route=register">Request Account</a></p>
                <p class="text-xs text-slate-600 mt-3">Default admin login for draft: <strong>admin / admin123!</strong></p>
            <?php else: ?>
                <h2 class="text-xl font-semibold mb-3">Request Account</h2>
                <form method="post" action="?route=register" class="space-y-2">
                    <input class="w-full border rounded p-2" name="username" placeholder="Username" required>
                    <input class="w-full border rounded p-2" type="password" name="password" placeholder="Password" required>
                    <button class="w-full bg-indigo-600 text-white rounded p-2">Submit Request</button>
                </form>
                <p class="text-sm mt-2"><a class="text-indigo-700" href="?route=login">Back to Login</a></p>
            <?php endif; ?>
        </div>

    <?php elseif ($route === 'admin'): ?>
        <?php $adminMsg = $_GET['msg'] ?? null; if ($adminMsg): ?><div class="mb-3 p-2 bg-indigo-100 border border-indigo-300 rounded"><?= htmlspecialchars($adminMsg) ?></div><?php endif; ?>
        <?php $users = read_users(); ?>
        <div class="bg-white rounded shadow p-4">
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
                                    <button class="px-2 py-1 bg-emerald-600 text-white rounded" name="action" value="approve" type="submit">Approve</button>
                                    <button class="px-2 py-1 bg-amber-600 text-white rounded" name="action" value="disable" type="submit">Disable</button>
                                    <button class="px-2 py-1 bg-rose-600 text-white rounded" name="action" value="delete" type="submit" onclick="return confirm('Delete user and vault?')">Delete</button>
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
            <aside class="col-span-12 md:col-span-3 bg-white rounded shadow p-3">
                <h3 class="font-semibold mb-2">Tree</h3>
                <ul id="tree" class="space-y-1 text-sm max-h-[45vh] overflow-auto">
                    <?php foreach ($files as $file): ?>
                        <li><button class="text-left w-full hover:underline" data-note="<?= htmlspecialchars($file) ?>"><?= htmlspecialchars($file) ?></button></li>
                    <?php endforeach; ?>
                </ul>
                <div class="mt-3 space-y-1">
                    <input id="newPath" class="w-full border rounded p-2 text-sm" placeholder="folder/my-note.md">
                    <button id="createBtn" class="w-full bg-indigo-600 text-white rounded p-2 text-sm">Create Note</button>
                </div>
                <div class="mt-3">
                    <h4 class="font-semibold mb-1">Tags</h4>
                    <div id="tags" class="flex flex-wrap gap-1 text-xs"></div>
                </div>
            </aside>
            <main class="col-span-12 md:col-span-9 bg-white rounded shadow p-3">
                <div class="flex flex-wrap gap-2 items-center mb-2">
                    <input id="searchQuery" class="border rounded p-2 text-sm flex-1" placeholder="Search notes...">
                    <select id="scope" class="border rounded p-2 text-sm"><option value="global">Global</option><option value="folder">In this folder</option></select>
                    <input id="scopeFolder" class="border rounded p-2 text-sm" placeholder="folder path (optional)">
                    <button id="searchBtn" class="bg-slate-700 text-white rounded px-3 py-2 text-sm">Search</button>
                    <span id="activeNote" class="text-sm text-slate-600"></span>
                </div>
                <div id="searchResults" class="text-sm mb-2"></div>
                <div id="vditor"></div>
                <textarea id="fallbackEditor" class="w-full min-h-[60vh] border rounded p-2 hidden"></textarea>
                <button id="saveBtn" class="mt-2 bg-emerald-600 text-white rounded px-3 py-2 text-sm">Save Now</button>
            </main>
        </div>
        <script src="https://unpkg.com/vditor/dist/index.min.js"></script>
        <script>
            const state = { activeNote: '', editor: null, autosaveTimer: null };

            async function api(payload) {
                const body = new URLSearchParams(payload);
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

            async function loadTags() {
                const out = await api({ action: 'tags' });
                const el = document.getElementById('tags');
                el.innerHTML = '';
                if (!out.ok) return;
                Object.entries(out.tags).forEach(([tag, count]) => {
                    const btn = document.createElement('button');
                    btn.className = 'px-2 py-1 rounded bg-slate-200';
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

            document.querySelectorAll('[data-note]').forEach((btn) => {
                btn.addEventListener('click', () => openNote(btn.dataset.note));
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
                    b.className = 'mr-2 text-indigo-700 underline';
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
                setTimeout(wireAutosave, 500);
                await loadTags();
            })();
        </script>
    <?php endif; ?>
</div>
</body>
</html>
