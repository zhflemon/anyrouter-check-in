#!/usr/bin/env python3
"""
批量删除 GitHub Actions workflow runs。

用法：
  # 从 git-credentials 自动读取 token（推荐）
  uv run scripts/clean_actions_runs.py

  # 指定 token
  GITHUB_TOKEN=ghp_xxx uv run scripts/clean_actions_runs.py

  # 指定仓库（默认从 git remote 自动获取）
  uv run scripts/clean_actions_runs.py --repo zhflemon/anyrouter-check-in

  # 保留最近的 N 个 runs
  uv run scripts/clean_actions_runs.py --keep 10
"""

import asyncio
import os
import re
import subprocess
import sys

import httpx


def get_git_remote() -> tuple[str, str] | None:
    """从 git remote origin 提取 owner/repo。"""
    try:
        result = subprocess.run(
            ['git', 'remote', 'get-url', 'origin'],
            capture_output=True, text=True, timeout=10,
        )
        url = result.stdout.strip()
        # git@github.com:zhflemon/anyrouter-check-in.git
        # https://github.com/zhflemon/anyrouter-check-in.git
        m = re.search(r'(?:github\.com[/:])([\w-]+/[\w-]+?)(?:\.git)?$', url)
        if m:
            return tuple(m.group(1).split('/'))  # type: ignore[return-value]
    except Exception:
        pass
    return None


def get_token_from_git_credentials() -> str | None:
    """从 ~/.git-credentials 中提取 GitHub token。"""
    cred_file = os.path.expanduser('~/.git-credentials')
    if not os.path.exists(cred_file):
        return None
    try:
        with open(cred_file) as f:
            for line in f:
                m = re.search(r'https://([^:]+):([^@]+)@github\.com', line)
                if m:
                    return m.group(2)
    except Exception:
        pass
    return None


async def delete_all_runs(
    owner: str,
    repo: str,
    token: str,
    *,
    keep: int = 0,
    batch_size: int = 20,
) -> None:
    """批量删除 workflow runs，可选保留最近 N 个。"""
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }

    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        # Step 1: 列出所有 runs
        print(f'[INFO] Listing workflow runs for {owner}/{repo}...')
        runs = []
        page = 1
        while True:
            r = await client.get(
                f'https://api.github.com/repos/{owner}/{repo}/actions/runs',
                params={'per_page': 100, 'page': page},
            )
            r.raise_for_status()
            data = r.json()
            batch = data.get('workflow_runs', [])
            if not batch:
                break
            runs.extend(batch)
            page += 1

        total = len(runs)
        if total == 0:
            print('[INFO] No workflow runs to clean.')
            return

        # Step 2: 确定要删除哪些（按创建时间排序，保留最近 keep 个）
        runs.sort(key=lambda r: r['created_at'], reverse=True)
        to_delete = runs[keep:] if keep > 0 else runs
        skipped = runs[:keep] if keep > 0 else []

        delete_ids = [r['id'] for r in to_delete]
        delete_count = len(delete_ids)
        print(f'[INFO] Total: {total}, To delete: {delete_count}' +
              (f', Keep: {len(skipped)}' if skipped else ''))

        if delete_count == 0:
            print('[INFO] Nothing to delete.')
            return

        # Step 3: 确认
        print(f'\n[WARN] About to delete {delete_count} workflow run(s) permanently.')
        try:
            confirm = input('Continue? (yes/no): ')
        except EOFError:
            confirm = 'no'
        if confirm.lower() not in ('yes', 'y'):
            print('[INFO] Cancelled.')
            return

        # Step 4: 并发删除
        deleted = 0
        errors = 0
        sem = asyncio.Semaphore(batch_size)

        async def delete_one(rid: int) -> None:
            nonlocal deleted, errors
            async with sem:
                r = await client.delete(
                    f'https://api.github.com/repos/{owner}/{repo}/actions/runs/{rid}',
                )
                if r.status_code == 204:
                    deleted += 1
                else:
                    errors += 1
                    if errors <= 3:
                        print(f'  [WARN] Failed run {rid}: HTTP {r.status_code}')

        for i in range(0, delete_count, 100):
            batch_ids = delete_ids[i:i + 100]
            tasks = [delete_one(rid) for rid in batch_ids]
            await asyncio.gather(*tasks)
            done = min(i + 100, delete_count)
            print(f'  Progress: {done}/{delete_count}')

        print(f'\n[RESULT] Deleted {deleted}/{delete_count} run(s) ({errors} error(s)).')


def main() -> None:
    # 解析参数
    repo_arg = None
    keep = 0
    for arg in sys.argv[1:]:
        if arg.startswith('--repo='):
            repo_arg = arg.split('=', 1)[1]
        elif arg.startswith('--keep='):
            keep = int(arg.split('=', 1)[1])

    # 获取 owner/repo
    owner_repo: tuple[str, str] | None = None
    if repo_arg:
        parts = repo_arg.split('/')
        if len(parts) == 2:
            owner_repo = (parts[0], parts[1])
    else:
        owner_repo = get_git_remote()

    if not owner_repo:
        print('[ERROR] Cannot determine repo. Use --repo=owner/repo', file=sys.stderr)
        sys.exit(1)

    owner, repo = owner_repo

    # 获取 token
    token = os.environ.get('GITHUB_TOKEN') or get_token_from_git_credentials()
    if not token:
        print(
            '[ERROR] No GitHub token found. Set GITHUB_TOKEN env var or '
            'configure git-credentials.',
            file=sys.stderr,
        )
        sys.exit(1)

    asyncio.run(delete_all_runs(owner, repo, token, keep=keep))


if __name__ == '__main__':
    main()
