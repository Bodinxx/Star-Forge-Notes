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

        if ($action === 'create_folder') {
            $err = create_folder($user['id'], $_POST['path'] ?? '');
            if ($err) {
                echo json_encode(['ok' => false, 'error' => $err]);
            } else {
                echo json_encode(['ok' => true, 'structure' => get_structure($user['id'])]);
            }
            exit;
        }

        if ($action === 'save') {
            $notePath = $_POST['path'] ?? '';
            $err = save_note($user['id'], $notePath, $_POST['content'] ?? '');
            echo json_encode([
                'ok' => $err === null,
                'error' => $err,
                'last_saved_at' => $err === null ? note_last_saved_at_utc($user['id'], $notePath) : null,
            ]);
            exit;
        }

        if ($action === 'load') {
            $notePath = $_POST['path'] ?? '';
            $content = read_note($user['id'], $notePath);
            echo json_encode([
                'ok' => $content !== null,
                'content' => $content,
                'last_saved_at' => $content !== null ? note_last_saved_at_utc($user['id'], $notePath) : null,
            ]);
            exit;
        }

        if ($action === 'move') {
            $from = $_POST['from'] ?? '';
            $toFolder = $_POST['to_folder'] ?? '';
            $err = move_note($user['id'], $from, $toFolder);
            $movedPath = move_note_destination_path($from, $toFolder);
            echo json_encode([
                'ok' => $err === null,
                'error' => $err,
                'moved_path' => $err === null ? $movedPath : null,
                'last_saved_at' => $err === null ? note_last_saved_at_utc($user['id'], $movedPath) : null,
                'structure' => $err === null ? get_structure($user['id']) : null,
            ]);
            exit;
        }

        if ($action === 'delete') {
            $path = $_POST['path'] ?? '';
            $err = delete_note($user['id'], $path);
            echo json_encode([
                'ok' => $err === null,
                'error' => $err,
                'structure' => $err === null ? get_structure($user['id']) : null,
            ]);
            exit;
        }

        if ($action === 'archive') {
            $path = $_POST['path'] ?? '';
            $err = archive_note($user['id'], $path);
            $movedPath = move_note_destination_path($path, ARCHIVE_FOLDER_NAME);
            echo json_encode([
                'ok' => $err === null,
                'error' => $err,
                'moved_path' => $err === null ? $movedPath : null,
                'last_saved_at' => $err === null ? note_last_saved_at_utc($user['id'], $movedPath) : null,
                'structure' => $err === null ? get_structure($user['id']) : null,
            ]);
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
            --sf-status-success-bg: #dcfce7;
            --sf-status-success-border: #86efac;
            --sf-status-success-text: #14532d;
            --sf-status-error-bg: #fee2e2;
            --sf-status-error-border: #fca5a5;
            --sf-status-error-text: #7f1d1d;
            --sf-status-info-bg: #dbeafe;
            --sf-status-info-border: #93c5fd;
            --sf-status-info-text: #1e3a8a;
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
            --sf-status-success-bg: #14532d; --sf-status-success-border: #16a34a; --sf-status-success-text: #dcfce7;
            --sf-status-error-bg: #7f1d1d; --sf-status-error-border: #ef4444; --sf-status-error-text: #fee2e2;
            --sf-status-info-bg: #1e3a8a; --sf-status-info-border: #3b82f6; --sf-status-info-text: #dbeafe;
        }
        :root[data-theme="dark-graphite"] {
            --sf-bg: #111827; --sf-panel: #1f2937; --sf-text: #f3f4f6; --sf-muted: #9ca3af; --sf-border: #4b5563;
            --sf-input-bg: #111827; --sf-tag-bg: #374151; --sf-tag-text: #f3f4f6; --sf-link: #a5b4fc; color-scheme: dark;
            --sf-status-success-bg: #14532d; --sf-status-success-border: #16a34a; --sf-status-success-text: #dcfce7;
            --sf-status-error-bg: #7f1d1d; --sf-status-error-border: #ef4444; --sf-status-error-text: #fee2e2;
            --sf-status-info-bg: #1e3a8a; --sf-status-info-border: #3b82f6; --sf-status-info-text: #dbeafe;
        }
        :root[data-theme="dark-forest"] {
            --sf-bg: #052e16; --sf-panel: #14532d; --sf-text: #dcfce7; --sf-muted: #86efac; --sf-border: #15803d;
            --sf-input-bg: #052e16; --sf-tag-bg: #166534; --sf-tag-text: #dcfce7; --sf-link: #5eead4; color-scheme: dark;
            --sf-status-success-bg: #14532d; --sf-status-success-border: #22c55e; --sf-status-success-text: #dcfce7;
            --sf-status-error-bg: #7f1d1d; --sf-status-error-border: #f87171; --sf-status-error-text: #fee2e2;
            --sf-status-info-bg: #1e3a8a; --sf-status-info-border: #60a5fa; --sf-status-info-text: #dbeafe;
        }
        :root[data-theme="dark-plum"] {
            --sf-bg: #2e1065; --sf-panel: #3b0764; --sf-text: #f5d0fe; --sf-muted: #e879f9; --sf-border: #a855f7;
            --sf-input-bg: #2e1065; --sf-tag-bg: #581c87; --sf-tag-text: #f5d0fe; --sf-link: #c4b5fd; color-scheme: dark;
            --sf-status-success-bg: #14532d; --sf-status-success-border: #22c55e; --sf-status-success-text: #dcfce7;
            --sf-status-error-bg: #7f1d1d; --sf-status-error-border: #f87171; --sf-status-error-text: #fee2e2;
            --sf-status-info-bg: #1e3a8a; --sf-status-info-border: #60a5fa; --sf-status-info-text: #dbeafe;
        }
        :root[data-theme="dark-ocean"] {
            --sf-bg: #082f49; --sf-panel: #0c4a6e; --sf-text: #e0f2fe; --sf-muted: #7dd3fc; --sf-border: #0284c7;
            --sf-input-bg: #082f49; --sf-tag-bg: #075985; --sf-tag-text: #e0f2fe; --sf-link: #93c5fd; color-scheme: dark;
            --sf-status-success-bg: #14532d; --sf-status-success-border: #22c55e; --sf-status-success-text: #dcfce7;
            --sf-status-error-bg: #7f1d1d; --sf-status-error-border: #f87171; --sf-status-error-text: #fee2e2;
            --sf-status-info-bg: #1e3a8a; --sf-status-info-border: #60a5fa; --sf-status-info-text: #dbeafe;
        }
        body.theme-page { background: var(--sf-bg); color: var(--sf-text); }
        .theme-container { --sf-shell-padding: 20px; height: 100vh; height: 100dvh; padding: var(--sf-shell-padding); display: flex; flex-direction: column; overflow-y: auto; box-sizing: border-box; }
        .theme-panel { background: var(--sf-panel); color: var(--sf-text); border: 1px solid var(--sf-border); }
        .theme-input { background: var(--sf-input-bg); color: var(--sf-text); border-color: var(--sf-border); }
        .theme-muted { color: var(--sf-muted); }
        .theme-tag { background: var(--sf-tag-bg); color: var(--sf-tag-text); }
        .theme-link { color: var(--sf-link); }
        .status-banner { border-width: 1px; border-style: solid; }
        .status-banner-success { background: var(--sf-status-success-bg); border-color: var(--sf-status-success-border); color: var(--sf-status-success-text); }
        .status-banner-error { background: var(--sf-status-error-bg); border-color: var(--sf-status-error-border); color: var(--sf-status-error-text); }
        .status-banner-info { background: var(--sf-status-info-bg); border-color: var(--sf-status-info-border); color: var(--sf-status-info-text); }
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
        .tree-note-row { display: flex; align-items: center; gap: 4px; }
        .tree-note-row .tree-note-button { flex: 1; }
        .tree-note-action { border-radius: 4px; padding: 2px 4px; line-height: 1; color: var(--sf-muted); }
        .tree-note-action:hover { background: color-mix(in srgb, var(--sf-tag-bg) 55%, transparent); color: var(--sf-text); }
        .tree-note-button[draggable="true"] { cursor: grab; }
        .tree-note-button:hover, .tree-folder > summary:hover { background: color-mix(in srgb, var(--sf-tag-bg) 55%, transparent); }
        .tree-note-button.is-active { background: color-mix(in srgb, var(--sf-tag-bg) 85%, transparent); font-weight: 600; }
        .tree-drop-zone.is-drop-target, #tree.tree-drop-target { background: color-mix(in srgb, var(--sf-link) 18%, transparent); outline: 1px dashed var(--sf-link); border-radius: 4px; }
        /* Full-viewport app layout */
        #appGrid { flex: 1; min-height: 0; grid-template-rows: 1fr; overflow: hidden; align-items: stretch; }
        #editorAside { display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
        #tree { flex: 1; min-height: 0; overflow-y: auto; max-height: none; }
        #editorMain { display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
        .editor-area { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden; }
        #editorTabBar { flex-shrink: 0; display: flex; align-items: center; gap: 2px; padding-bottom: 4px; border-bottom: 1px solid var(--sf-border); margin-bottom: 4px; }
        .tab-btn { padding: 4px 14px; font-size: 0.875rem; cursor: pointer; border-bottom: 2px solid transparent; opacity: 0.6; background: none; }
        .tab-btn.tab-active { border-bottom: 2px solid var(--sf-link); opacity: 1; font-weight: 500; color: var(--sf-text); }
        .editor-panel { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden; }
        #rawEditor { flex: 1; min-height: 0; resize: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.875rem; line-height: 1.6; }
        #vditor { flex: 1; min-height: 0; }
        /* Aside tab bar and panels */
        #asideTabBar { flex-shrink: 0; display: flex; align-items: center; gap: 2px; padding-bottom: 4px; border-bottom: 1px solid var(--sf-border); margin-bottom: 6px; }
        .aside-panel { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden; }
        #searchResults { flex: 1; min-height: 0; overflow-y: auto; }
        /* Save button states */
        #saveBtn { transition: background-color 0.2s; }
        #saveBtn.save-idle { background-color: #6b7280; opacity: 0.7; cursor: default; }
        #saveBtn.save-dirty { background-color: #16a34a; }
        /* Vditor dark mode: fix all text colors */
        [data-theme^="dark-"] .vditor-reset,
        [data-theme^="dark-"] .vditor-wysiwyg,
        [data-theme^="dark-"] .vditor-ir { color: var(--sf-text) !important; }
        [data-theme^="dark-"] .vditor-reset p,
        [data-theme^="dark-"] .vditor-reset li,
        [data-theme^="dark-"] .vditor-reset span,
        [data-theme^="dark-"] .vditor-reset strong,
        [data-theme^="dark-"] .vditor-reset em,
        [data-theme^="dark-"] .vditor-reset del,
        [data-theme^="dark-"] .vditor-reset blockquote,
        [data-theme^="dark-"] .vditor-reset td,
        [data-theme^="dark-"] .vditor-reset th,
        [data-theme^="dark-"] .vditor-wysiwyg p,
        [data-theme^="dark-"] .vditor-wysiwyg li,
        [data-theme^="dark-"] .vditor-wysiwyg span,
        [data-theme^="dark-"] .vditor-wysiwyg strong,
        [data-theme^="dark-"] .vditor-wysiwyg em,
        [data-theme^="dark-"] .vditor-wysiwyg del,
        [data-theme^="dark-"] .vditor-wysiwyg blockquote,
        [data-theme^="dark-"] .vditor-wysiwyg td,
        [data-theme^="dark-"] .vditor-wysiwyg th,
        [data-theme^="dark-"] .vditor-wysiwyg h1,
        [data-theme^="dark-"] .vditor-wysiwyg h2,
        [data-theme^="dark-"] .vditor-wysiwyg h3,
        [data-theme^="dark-"] .vditor-wysiwyg h4,
        [data-theme^="dark-"] .vditor-wysiwyg h5,
        [data-theme^="dark-"] .vditor-wysiwyg h6,
        [data-theme^="dark-"] .vditor-ir p,
        [data-theme^="dark-"] .vditor-ir li,
        [data-theme^="dark-"] .vditor-ir span,
        [data-theme^="dark-"] .vditor-ir strong,
        [data-theme^="dark-"] .vditor-ir em,
        [data-theme^="dark-"] .vditor-ir del,
        [data-theme^="dark-"] .vditor-ir blockquote,
        [data-theme^="dark-"] .vditor-ir td,
        [data-theme^="dark-"] .vditor-ir th,
        [data-theme^="dark-"] .vditor-ir h1,
        [data-theme^="dark-"] .vditor-ir h2,
        [data-theme^="dark-"] .vditor-ir h3,
        [data-theme^="dark-"] .vditor-ir h4,
        [data-theme^="dark-"] .vditor-ir h5,
        [data-theme^="dark-"] .vditor-ir h6 { color: var(--sf-text) !important; }
        /* Vditor dark mode: reverse code block colors */
        [data-theme^="dark-"] .vditor-reset pre,
        [data-theme^="dark-"] .vditor-reset pre code,
        [data-theme^="dark-"] .vditor-wysiwyg pre,
        [data-theme^="dark-"] .vditor-wysiwyg pre code,
        [data-theme^="dark-"] .vditor-ir pre,
        [data-theme^="dark-"] .vditor-ir pre code,
        [data-theme^="dark-"] .vditor-reset code,
        [data-theme^="dark-"] .vditor-wysiwyg code,
        [data-theme^="dark-"] .vditor-ir code { background-color: #0f172a !important; color: #e2e8f0 !important; }
        [data-theme^="dark-"] .vditor-reset pre .hljs,
        [data-theme^="dark-"] .vditor-wysiwyg pre .hljs,
        [data-theme^="dark-"] .vditor-ir pre .hljs { background-color: #0f172a !important; color: #e2e8f0 !important; }
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

    <?php if ($message): ?><div class="mb-3 p-2 rounded status-banner status-banner-success"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="mb-3 p-2 rounded status-banner status-banner-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>

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
        <?php $adminMsg = $_GET['msg'] ?? null; if ($adminMsg): ?><div class="mb-3 p-2 rounded status-banner status-banner-info"><?= htmlspecialchars($adminMsg) ?></div><?php endif; ?>
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
            $folders = $structure['folders'] ?? [];
        ?>
        <div id="appGrid" class="grid grid-cols-12 gap-4">
        <aside id="editorAside" class="col-span-12 md:col-span-3 theme-panel rounded shadow p-3">
                <div id="asideTabBar">
                    <button id="asideTreeBtn" class="tab-btn tab-active">Tree</button>
                    <button id="asideSearchBtn" class="tab-btn">Search</button>
                </div>
                <!-- Tree panel -->
                <div id="asideTreePanel" class="aside-panel">
                    <ul id="tree" class="tree-root text-sm"></ul>
                    <div class="mt-3 space-y-1 flex-shrink-0">
                        <datalist id="folderList"></datalist>
                        <div class="flex items-center gap-1 flex-wrap">
                            <input id="newFolder" list="folderList" class="theme-input border rounded p-2 text-sm flex-1" style="min-width:80px" placeholder="Folder (optional)">
                            <span class="text-xs theme-muted">/</span>
                            <input id="newFileName" class="theme-input border rounded p-2 text-sm flex-1" style="min-width:60px" placeholder="File name">
                            <span class="text-xs theme-muted whitespace-nowrap">.md</span>
                        </div>
                        <div class="flex gap-1">
                            <button id="createBtn" class="flex-1 bg-indigo-600 text-white rounded p-2 text-sm">Create Note</button>
                            <button id="createFolderBtn" class="flex-1 bg-slate-700 text-white rounded p-2 text-sm">Create Folder</button>
                        </div>
                    </div>
                    <div class="mt-3 flex-shrink-0">
                        <h4 class="font-semibold mb-1">Tags</h4>
                        <div id="tags" class="flex flex-wrap gap-1 text-xs"></div>
                    </div>
                </div>
                <!-- Search panel -->
                <div id="asideSearchPanel" class="aside-panel hidden">
                    <div class="space-y-1 mb-2 flex-shrink-0">
                        <input id="searchQuery" class="theme-input w-full border rounded p-2 text-sm" placeholder="Search notes...">
                        <div class="flex gap-1">
                            <select id="scope" class="theme-input border rounded p-2 text-sm flex-1"><option value="global">Global</option><option value="folder">In this folder</option></select>
                            <input id="scopeFolder" class="theme-input border rounded p-2 text-sm flex-1" placeholder="folder (optional)">
                        </div>
                        <button id="searchBtn" class="w-full bg-slate-700 text-white rounded px-3 py-2 text-sm">Search</button>
                    </div>
                    <div id="searchResults" class="text-sm"></div>
                </div>
            </aside>
            <main id="editorMain" class="col-span-12 md:col-span-9 theme-panel rounded shadow p-3">
                <div id="editorArea" class="editor-area">
                    <div id="editorTabBar">
                        <button id="tabRichBtn" class="tab-btn tab-active">Rich Editor</button>
                        <button id="tabSourceBtn" class="tab-btn">Markdown Source</button>
                    </div>
                    <div id="tabRichPanel" class="editor-panel">
                        <div id="vditor"></div>
                    </div>
                    <div id="tabSourcePanel" class="editor-panel hidden">
                        <textarea id="rawEditor" class="theme-input w-full border rounded p-2"></textarea>
                    </div>
                </div>
                <div class="flex gap-2 mt-2 flex-shrink-0 items-center">
                    <button id="saveBtn" class="save-idle text-white rounded px-3 py-2 text-sm">Save Now</button>
                    <span id="activeNote" class="text-sm theme-muted truncate"></span>
                    <span id="lastSavedAt" class="text-xs theme-muted whitespace-nowrap"></span>
                </div>
            </main>
        </div>
        <script id="tree-structure-data" type="application/json"><?= json_encode(['files' => $files, 'folders' => $folders], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE) ?></script>
        <script src="https://unpkg.com/vditor/dist/index.min.js"></script>
        <script>
            const state = { activeNote: '', editor: null, autosaveTimer: null, activeTab: 'rich', isDirty: false, lastSavedAt: null };
            const csrfToken = <?= json_encode($csrfToken) ?>;
            const TREE_NOTE_SELECTOR = 'button[data-note]';
            // Approximate pixel offset (header + search bar + tab bar + save row + padding) used
            // to compute an initial pixel height for Vditor before ResizeObserver takes over.
            const VDITOR_HEIGHT_OFFSET = 250;
            const AUTOSAVE_DEBOUNCE_MS = 1200;
            const LAST_SAVED_TIMEZONE = 'America/Phoenix';
            const LAST_SAVED_LABEL = 'MST';
            let treeFiles = [];
            let treeFolders = [];
            try {
                const treeStructure = JSON.parse(document.getElementById('tree-structure-data')?.textContent || '{}');
                treeFiles = Array.isArray(treeStructure.files) ? treeStructure.files : [];
                treeFolders = Array.isArray(treeStructure.folders) ? treeStructure.folders : [];
            } catch (error) {
                console.error('Invalid tree data JSON payload.', error);
            }
            const rawEditorEl = document.getElementById('rawEditor');

            async function api(payload) {
                const body = new URLSearchParams({ ...payload, csrf: csrfToken });
                const res = await fetch('?route=api', { method: 'POST', body });
                return res.json();
            }

            function contentGet() {
                if (state.activeTab === 'source') return rawEditorEl.value;
                if (state.editor) return state.editor.getValue();
                return rawEditorEl.value;
            }

            function contentSet(value) {
                rawEditorEl.value = value || '';
                if (state.editor) state.editor.setValue(value || '');
            }

            function adjustEditorHeight() {
                const panel = document.getElementById('tabRichPanel');
                if (!panel || !state.editor) return;
                const h = panel.clientHeight;
                if (h > 100) state.editor.vditor.element.style.height = h + 'px';
            }

            function switchTab(tab) {
                const richPanel = document.getElementById('tabRichPanel');
                const sourcePanel = document.getElementById('tabSourcePanel');
                const richBtn = document.getElementById('tabRichBtn');
                const sourceBtn = document.getElementById('tabSourceBtn');
                if (tab === 'rich') {
                    if (state.editor) state.editor.setValue(rawEditorEl.value);
                    richPanel.classList.remove('hidden');
                    sourcePanel.classList.add('hidden');
                    richBtn.classList.add('tab-active');
                    sourceBtn.classList.remove('tab-active');
                    state.activeTab = 'rich';
                    adjustEditorHeight();
                } else {
                    if (state.editor) rawEditorEl.value = state.editor.getValue();
                    richPanel.classList.add('hidden');
                    sourcePanel.classList.remove('hidden');
                    richBtn.classList.remove('tab-active');
                    sourceBtn.classList.add('tab-active');
                    state.activeTab = 'source';
                }
            }

            function folderSortCompare(left, right) {
                const leftIsArchive = left.toLowerCase() === 'archive';
                const rightIsArchive = right.toLowerCase() === 'archive';
                if (leftIsArchive && !rightIsArchive) return 1;
                if (!leftIsArchive && rightIsArchive) return -1;
                return caseInsensitiveCompare(left, right);
            }

            function ensureFolderNode(root, folderPath) {
                const parts = folderPath.split('/').filter(Boolean);
                let node = root;
                parts.forEach((part) => {
                    if (!node.folders.has(part)) {
                        node.folders.set(part, { folders: new Map(), files: [] });
                    }
                    node = node.folders.get(part);
                });
            }

            function buildTree(files, folders) {
                const root = { folders: new Map(), files: [] };
                folders.forEach((folderPath) => {
                    ensureFolderNode(root, folderPath);
                });
                files.forEach((path) => {
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

            function renderTreeNode(node, container, parentFolder = '') {
                Array.from(node.folders.entries())
                    .sort(([a], [b]) => folderSortCompare(a, b))
                    .forEach(([folderName, folderNode]) => {
                        const folderPath = parentFolder ? `${parentFolder}/${folderName}` : folderName;
                        const item = document.createElement('li');
                        item.className = 'tree-item';

                        const details = document.createElement('details');
                        details.className = 'tree-folder';
                        details.dataset.folderPath = folderPath;
                        details.open = true;

                        const summary = document.createElement('summary');
                        summary.className = 'tree-drop-zone';
                        summary.dataset.dropFolder = folderPath;
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
                        renderTreeNode(folderNode, branch, folderPath);
                        details.appendChild(branch);
                        item.appendChild(details);
                        container.appendChild(item);
                    });

                node.files
                    .sort((a, b) => caseInsensitiveCompare(a.name, b.name))
                    .forEach((file) => {
                        const item = document.createElement('li');
                        item.className = 'tree-item';

                        const row = document.createElement('div');
                        row.className = 'tree-note-row';

                        const btn = document.createElement('button');
                        btn.className = 'tree-note-button';
                        btn.dataset.note = file.path;
                        btn.draggable = true;

                        const fileIcon = document.createElement('span');
                        fileIcon.className = 'tree-file-icon';
                        fileIcon.textContent = '📄';

                        const label = document.createElement('span');
                        label.textContent = file.name;
                        btn.append(fileIcon, label);

                        const archiveBtn = document.createElement('button');
                        archiveBtn.type = 'button';
                        archiveBtn.className = 'tree-note-action tree-note-archive';
                        archiveBtn.dataset.noteArchive = file.path;
                        archiveBtn.title = 'Archive note';
                        archiveBtn.textContent = '🗄️';

                        const deleteBtn = document.createElement('button');
                        deleteBtn.type = 'button';
                        deleteBtn.className = 'tree-note-action tree-note-delete';
                        deleteBtn.dataset.noteDelete = file.path;
                        deleteBtn.title = 'Delete note';
                        deleteBtn.textContent = '🗑️';

                        row.append(btn, archiveBtn, deleteBtn);
                        item.appendChild(row);
                        container.appendChild(item);
                    });
            }

            function renderTree(files, folders) {
                const tree = document.getElementById('tree');
                tree.innerHTML = '';
                tree.classList.remove('tree-drop-target');
                if (!files.length && !folders.length) {
                    const empty = document.createElement('li');
                    empty.className = 'theme-muted';
                    empty.textContent = 'No notes yet.';
                    tree.appendChild(empty);
                    return;
                }
                const root = buildTree(files, folders);
                renderTreeNode(root, tree, '');
            }

            function applyStructure(structure) {
                treeFiles = Array.isArray(structure?.files) ? structure.files : [];
                treeFolders = Array.isArray(structure?.folders) ? structure.folders : [];
                renderTree(treeFiles, treeFolders);
                populateFolderList(treeFiles, treeFolders);
            }

            function highlightActiveTreeNote() {
                const buttons = document.querySelectorAll(`#tree ${TREE_NOTE_SELECTOR}`);
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

            function formatMstTimestamp(isoValue) {
                if (!isoValue) return '';
                const date = new Date(isoValue);
                if (Number.isNaN(date.getTime())) return '';
                const formatted = new Intl.DateTimeFormat('en-US', {
                    timeZone: LAST_SAVED_TIMEZONE,
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: true,
                }).format(date);
                return `Last saved (${LAST_SAVED_LABEL}): ${formatted}`;
            }

            function updateLastSavedLabel() {
                const el = document.getElementById('lastSavedAt');
                el.textContent = formatMstTimestamp(state.lastSavedAt);
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
                        switchAsideTab('search');
                        document.getElementById('searchBtn').click();
                    };
                    el.appendChild(btn);
                });
            }

            function updateSaveButton() {
                const btn = document.getElementById('saveBtn');
                if (state.isDirty) {
                    btn.classList.remove('save-idle');
                    btn.classList.add('save-dirty');
                    btn.disabled = false;
                } else {
                    btn.classList.remove('save-dirty');
                    btn.classList.add('save-idle');
                    btn.disabled = true;
                }
            }

            function markDirty() {
                if (!state.isDirty) {
                    state.isDirty = true;
                    updateSaveButton();
                }
            }

            function markClean() {
                state.isDirty = false;
                updateSaveButton();
            }

            function switchAsideTab(tab) {
                const treePanel = document.getElementById('asideTreePanel');
                const searchPanel = document.getElementById('asideSearchPanel');
                const treeBtn = document.getElementById('asideTreeBtn');
                const searchBtn = document.getElementById('asideSearchBtn');
                treePanel.classList.toggle('hidden', tab !== 'tree');
                searchPanel.classList.toggle('hidden', tab !== 'search');
                treeBtn.classList.toggle('tab-active', tab === 'tree');
                searchBtn.classList.toggle('tab-active', tab === 'search');
            }

            async function openNote(path) {
                state.activeNote = path;
                document.getElementById('activeNote').textContent = path;
                state.lastSavedAt = null;
                updateLastSavedLabel();
                highlightActiveTreeNote();
                const out = await api({ action: 'load', path });
                if (!out.ok) return;
                contentSet(out.content || '');
                state.lastSavedAt = out.last_saved_at || null;
                updateLastSavedLabel();
                markClean();
            }

            async function saveCurrent() {
                if (!state.activeNote) return;
                const out = await api({ action: 'save', path: state.activeNote, content: contentGet() });
                if (!out.ok) {
                    alert(out.error || 'Save failed.');
                    return;
                }
                state.lastSavedAt = out.last_saved_at || null;
                updateLastSavedLabel();
                markClean();
            }

            function wireAutosave() {
                if (state.editor) {
                    state.editor.vditor.element.addEventListener('input', () => {
                        markDirty();
                        clearTimeout(state.autosaveTimer);
                        state.autosaveTimer = setTimeout(saveCurrent, AUTOSAVE_DEBOUNCE_MS);
                    });
                }
            }

            let rawSyncTimer = null;
            rawEditorEl.addEventListener('input', () => {
                markDirty();
                clearTimeout(state.autosaveTimer);
                state.autosaveTimer = setTimeout(saveCurrent, AUTOSAVE_DEBOUNCE_MS);
                if (state.editor) {
                    clearTimeout(rawSyncTimer);
                    rawSyncTimer = setTimeout(() => state.editor.setValue(rawEditorEl.value), AUTOSAVE_DEBOUNCE_MS);
                }
            });

            document.getElementById('tabRichBtn').addEventListener('click', () => switchTab('rich'));
            document.getElementById('tabSourceBtn').addEventListener('click', () => switchTab('source'));
            document.getElementById('asideTreeBtn').addEventListener('click', () => switchAsideTab('tree'));
            document.getElementById('asideSearchBtn').addEventListener('click', () => switchAsideTab('search'));
            window.addEventListener('resize', adjustEditorHeight);

            document.getElementById('tree').addEventListener('click', (event) => {
                const deleteBtn = event.target.closest('.tree-note-delete');
                if (deleteBtn) {
                    deleteTreeNote(deleteBtn.dataset.noteDelete || '');
                    return;
                }
                const archiveBtn = event.target.closest('.tree-note-archive');
                if (archiveBtn) {
                    archiveTreeNote(archiveBtn.dataset.noteArchive || '');
                    return;
                }
                const target = event.target.closest(TREE_NOTE_SELECTOR);
                if (!target) return;
                openNote(target.dataset.note);
            });

            let dragNotePath = '';

            function parentFolder(path) {
                const index = path.lastIndexOf('/');
                return index === -1 ? '' : path.slice(0, index);
            }

            function clearTreeDropTargets() {
                document.getElementById('tree').classList.remove('tree-drop-target');
                document.querySelectorAll('.tree-drop-zone.is-drop-target').forEach((el) => el.classList.remove('is-drop-target'));
            }

            function getDropFolderFromTarget(target) {
                const summary = target.closest('.tree-drop-zone');
                if (summary) return summary.dataset.dropFolder || '';
                const details = target.closest('details.tree-folder');
                if (details) return details.dataset.folderPath || '';
                return '';
            }

            function paintDropTarget(target) {
                clearTreeDropTargets();
                const summary = target.closest('.tree-drop-zone');
                if (summary) {
                    summary.classList.add('is-drop-target');
                    return;
                }
                document.getElementById('tree').classList.add('tree-drop-target');
            }

            async function moveTreeNote(fromPath, destinationFolder) {
                if (!fromPath) return;
                if (state.activeNote === fromPath && state.isDirty) {
                    await saveCurrent();
                    if (state.isDirty) {
                        alert('Move canceled because the note could not be saved.');
                        return;
                    }
                }

                const out = await api({ action: 'move', from: fromPath, to_folder: destinationFolder });
                if (!out.ok) {
                    alert(out.error || 'Move failed.');
                    return;
                }

                applyStructure(out.structure);

                if (state.activeNote === fromPath) {
                    state.activeNote = out.moved_path || fromPath;
                    document.getElementById('activeNote').textContent = state.activeNote;
                    state.lastSavedAt = out.last_saved_at || null;
                    updateLastSavedLabel();
                }
                highlightActiveTreeNote();
            }

            async function archiveTreeNote(path) {
                if (!path) return;
                if (state.activeNote === path && state.isDirty) {
                    await saveCurrent();
                    if (state.isDirty) {
                        alert('Archive canceled because the note could not be saved.');
                        return;
                    }
                }

                const out = await api({ action: 'archive', path });
                if (!out.ok) {
                    alert(out.error || 'Archive failed.');
                    return;
                }

                applyStructure(out.structure);
                if (state.activeNote === path) {
                    state.activeNote = out.moved_path || path;
                    document.getElementById('activeNote').textContent = state.activeNote;
                    state.lastSavedAt = out.last_saved_at || null;
                    updateLastSavedLabel();
                }
                highlightActiveTreeNote();
                await loadTags();
            }

            async function deleteTreeNote(path) {
                if (!path || !confirm(`Delete note "${path}"?`)) return;
                if (state.activeNote === path && state.isDirty) {
                    await saveCurrent();
                    if (state.isDirty) {
                        alert('Delete canceled because the note could not be saved.');
                        return;
                    }
                }

                const out = await api({ action: 'delete', path });
                if (!out.ok) {
                    alert(out.error || 'Delete failed.');
                    return;
                }

                applyStructure(out.structure);
                if (state.activeNote === path) {
                    state.activeNote = '';
                    document.getElementById('activeNote').textContent = '';
                    state.lastSavedAt = null;
                    updateLastSavedLabel();
                    contentSet('');
                    markClean();
                }
                highlightActiveTreeNote();
                await loadTags();
            }

            document.getElementById('tree').addEventListener('dragstart', (event) => {
                const noteButton = event.target.closest(TREE_NOTE_SELECTOR);
                if (!noteButton) return;
                dragNotePath = noteButton.dataset.note || '';
                if (event.dataTransfer) {
                    event.dataTransfer.effectAllowed = 'move';
                    event.dataTransfer.setData('text/plain', dragNotePath);
                }
            });

            document.getElementById('tree').addEventListener('dragover', (event) => {
                const fromPath = dragNotePath;
                if (!fromPath) return;
                const dropFolder = getDropFolderFromTarget(event.target);
                if (parentFolder(fromPath) === dropFolder) return;
                event.preventDefault();
                if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
                paintDropTarget(event.target);
            });

            document.getElementById('tree').addEventListener('dragleave', (event) => {
                if (!event.relatedTarget || !event.currentTarget.contains(event.relatedTarget)) {
                    clearTreeDropTargets();
                }
            });

            document.getElementById('tree').addEventListener('drop', async (event) => {
                const fromPath = dragNotePath;
                dragNotePath = '';
                clearTreeDropTargets();
                if (!fromPath) return;
                const dropFolder = getDropFolderFromTarget(event.target);
                if (parentFolder(fromPath) === dropFolder) return;
                event.preventDefault();
                await moveTreeNote(fromPath, dropFolder);
            });

            document.getElementById('tree').addEventListener('dragend', () => {
                dragNotePath = '';
                clearTreeDropTargets();
            });

            function populateFolderList(files, folders) {
                const datalist = document.getElementById('folderList');
                if (!datalist) return;
                const allFolders = new Set(Array.isArray(folders) ? folders : []);
                files.forEach((path) => {
                    const parts = path.split('/').filter(Boolean);
                    for (let i = 1; i < parts.length; i++) {
                        allFolders.add(parts.slice(0, i).join('/'));
                    }
                });
                datalist.innerHTML = '';
                Array.from(allFolders).sort((a, b) => folderSortCompare(a, b)).forEach((folder) => {
                    const opt = document.createElement('option');
                    opt.value = folder;
                    datalist.appendChild(opt);
                });
            }

            document.getElementById('createBtn').addEventListener('click', async () => {
                const folder = document.getElementById('newFolder').value.trim().replace(/^\/+|\/+$/g, '');
                const fileName = document.getElementById('newFileName').value.trim();
                if (!fileName) return;
                const path = folder ? `${folder}/${fileName}.md` : `${fileName}.md`;
                const out = await api({ action: 'create', path });
                if (!out.ok) return alert(out.error || 'Failed');
                applyStructure(out.structure);
                document.getElementById('newFileName').value = '';
                await openNote(path);
                await loadTags();
            });

            document.getElementById('createFolderBtn').addEventListener('click', async () => {
                const folder = document.getElementById('newFolder').value.trim().replace(/^\/+|\/+$/g, '');
                if (!folder) {
                    alert('Folder path is required.');
                    return;
                }
                const out = await api({ action: 'create_folder', path: folder });
                if (!out.ok) return alert(out.error || 'Failed');
                applyStructure(out.structure);
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
                    b.className = 'block w-full text-left py-0.5 theme-link underline text-sm';
                    b.textContent = path;
                    b.onclick = () => openNote(path);
                    el.appendChild(b);
                });
            });

            function getVditorTheme() {
                const t = document.documentElement.getAttribute('data-theme') || 'light-slate';
                return t.startsWith('dark-') ? 'dark' : 'classic';
            }

            window.sfOnThemeChange = (theme) => {
                if (state.editor) {
                    state.editor.setTheme(theme.startsWith('dark-') ? 'dark' : 'classic');
                }
            };

            (async () => {
                try {
                    if (window.Vditor) {
                        state.editor = new Vditor('vditor', {
                            height: Math.max(300, window.innerHeight - VDITOR_HEIGHT_OFFSET),
                            mode: 'wysiwyg',
                            lang: 'en_US',
                            cache: { enable: false },
                            theme: getVditorTheme(),
                            after() {
                                adjustEditorHeight();
                                // ResizeObserver is intentionally not disconnected; acceptable for a
                                // single-page-per-load lifecycle where the editor is never recreated.
                                const panel = document.getElementById('tabRichPanel');
                                if (panel) {
                                    const ro = new ResizeObserver(adjustEditorHeight);
                                    ro.observe(panel);
                                }
                            },
                        });
                    } else {
                        switchTab('source');
                    }
                } catch (e) {
                    state.editor = null;
                    switchTab('source');
                }
                renderTree(treeFiles, treeFolders);
                populateFolderList(treeFiles, treeFolders);
                setTimeout(wireAutosave, 500);
                updateSaveButton();
                updateLastSavedLabel();
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
        select.addEventListener('change', (event) => {
            applyTheme(event.target.value, true);
            if (typeof window.sfOnThemeChange === 'function') {
                window.sfOnThemeChange(event.target.value);
            }
        });
    })();
</script>
</body>
</html>
