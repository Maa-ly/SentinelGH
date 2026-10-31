"""Clean the login data, calculate summaries and draw four charts."""
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

BASE = Path(__file__).resolve().parent
COLUMNS = ['timestamp', 'username', 'ip_address', 'country', 'branch', 'channel', 'status']


def clean_data(path):
    """Remove duplicates and invalid essentials, keeping a cleaning summary."""
    try:
        frame = pd.read_csv(path, dtype=str, on_bad_lines='error')
    except (OSError, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise ValueError(f'Cannot read login data: {error}') from error
    if not set(COLUMNS).issubset(frame.columns):
        raise ValueError('The login file is missing required columns')
    frame = frame[COLUMNS].copy()
    original = len(frame)
    for column in COLUMNS:
        frame[column] = frame[column].str.strip().replace('', pd.NA)
    frame['status'] = frame['status'].str.upper()
    frame['channel'] = frame['channel'].str.lower()
    frame['timestamp'] = pd.to_datetime(frame['timestamp'], format='%Y-%m-%d %H:%M:%S', errors='coerce')
    before = len(frame)
    frame = frame.dropna(subset=['timestamp', 'username', 'ip_address', 'status'])
    frame = frame[frame['status'].isin(['SUCCESS', 'FAIL', 'LOCKED'])]
    invalid = before - len(frame)
    frame[['country', 'branch', 'channel']] = frame[['country', 'branch', 'channel']].fillna('Unknown')
    before = len(frame)
    frame = frame.drop_duplicates().sort_values('timestamp')
    return frame, {'original': original, 'invalid': invalid, 'duplicates': before-len(frame), 'clean': len(frame)}


def save_chart(name, title, xlabel, ylabel):
    """Label and save the current chart, then release its memory."""
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(BASE / 'charts' / name, dpi=150)
    plt.close()


def analyse(auditor, events, alerts):
    """Create whole-period charts and a report for the latest logged day."""
    frame, cleaning = clean_data(BASE.parent / 'logs' / 'auth_log.csv')
    (BASE / 'charts').mkdir(exist_ok=True)
    frame.to_csv(BASE / 'cleaned_logs.csv', index=False)
    (BASE / 'cleaning_summary.txt').write_text('\n'.join(f'{key}: {value}' for key, value in cleaning.items()), encoding='utf-8')
    if frame.empty:
        print('No valid login records. Charts and daily report cannot be generated.')
        return
    sns.set_theme(style='whitegrid')
    frame['failed'] = frame['status'].isin(['FAIL', 'LOCKED'])
    branch = frame.groupby('branch')['failed'].agg(['size', 'sum'])
    branch.columns = ['attempts', 'failures']
    branch['failure_rate_percent'] = (100 * branch['failures'] / branch['attempts']).round(2)
    branch.to_csv(BASE / 'branch_summary.csv')
    per_user = frame.groupby('username')['failed'].sum()
    average = float(np.mean(per_user.to_numpy()))
    failed = frame[frame['failed']]
    top_ips = failed.groupby('ip_address').size().sort_values(ascending=False).head(10)
    top_ips.to_csv(BASE / 'top_10_attacking_ips.csv', header=['failed_attempts'])
    scores = pd.DataFrame(auditor.scores(), columns=['username', 'score'])
    scores.to_csv(BASE / 'password_scores.csv', index=False)
    daily = frame.set_index('timestamp')['failed'].resample('D').sum()
    plt.figure(figsize=(9, 4))
    plt.plot(daily.index, daily.values, marker='o')
    plt.xticks(rotation=45)
    save_chart('failed_logins_per_day.png', 'Failed logins per day', 'Date', 'Rejected attempts')
    plt.figure(figsize=(7, 4))
    sns.barplot(x=branch.index, y=branch['failures'].values, color='steelblue')
    save_chart('failed_logins_by_branch.png', 'Failed logins by branch', 'Branch', 'Rejected attempts')
    hours = frame['timestamp'].dt.hour.value_counts().reindex(range(24), fill_value=0)
    plt.figure(figsize=(9, 4))
    plt.bar(hours.index, hours.values, color='teal')
    plt.xticks(range(24))
    save_chart('login_attempts_by_hour.png', 'Login attempts by hour', 'Hour (0–23)', 'All attempts')
    distribution = scores['score'].value_counts().reindex(range(7), fill_value=0)
    plt.figure(figsize=(7, 4))
    sns.barplot(x=distribution.index, y=distribution.values, color='darkorange')
    save_chart('password_strength_distribution.png', 'Password strength distribution', 'Policy score (0–6)', 'Staff accounts')
    latest = frame['timestamp'].max().date()
    today = frame[frame['timestamp'].dt.date == latest]
    today_alerts = [alert for alert in alerts if alert.time.date() == latest]
    weak = int((scores['score'] < 6).sum())
    known_branches = branch.drop(index='Unknown', errors='ignore')
    comparison = known_branches if not known_branches.empty else branch
    worst = comparison['failure_rate_percent'].idxmax()
    lines = [
        'SentinelGH — Draft Daily Incident Report', 'Nkabom Savings & Loans',
        f'Report date: {latest} (latest date in the supplied log)', '',
        f'Daily activity: {len(today)} attempts; {int(today.failed.sum())} rejected attempts.',
        f'Daily failure rate: {100*today.failed.mean():.2f}%.',
        f'Alerts starting today: {len(today_alerts)}. Alerts may describe windows crossing midnight.', '',
        'Daily findings (up to five):',
    ]
    lines.extend(str(alert) for alert in today_alerts[:5])
    if not today_alerts:
        lines.append('No alerts start on this date under our configured rules.')
    lines.extend([
        '', 'Whole-file context (not daily totals):',
        f'Coverage: {frame.timestamp.min().date()} to {latest}; {len(frame)} cleaned attempts.',
        f'Cleaning: {cleaning["invalid"]} invalid rows and {cleaning["duplicates"]} duplicate valid rows removed.',
        f'Average rejected attempts per user: {average:.2f}, including users with zero failures.',
        f'Highest known-branch failure rate: {worst}, {branch.loc[worst, "failure_rate_percent"]:.2f}%.',
        f'Unknown branch rows: {int((frame["branch"] == "Unknown").sum())}; excluded from the named-branch comparison.',
        f'Staff audit: {weak} of {len(scores)} accounts score below 6/6.',
        'Top candidate attacking IPs (ranked by rejected attempts):',
    ])
    lines.extend(f'  {ip}: {count}' for ip, count in top_ips.head(3).items())
    lines.extend([
        '', 'Recommended actions:',
        '1. Ask staff to confirm unusual night or foreign access; investigate affected accounts.',
        '2. Replace fictional practice passwords that fail the policy and consider multi-factor login.',
        '3. Review high-failure IPs and repeated lockouts before deciding on restrictions.',
        '', 'Notes: FAIL and LOCKED both count as rejected attempts. A foreign country comes',
        'from the supplied CSV; it is not an independent location check. Alerts are leads,',
        'not proof of an attack. Charts cover the whole file. Unknown countries are not foreign.',
    ])
    (BASE / 'draft_daily_report.txt').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(f'Charts and draft report saved. Key finding: {worst} had the highest known-branch failure rate ({branch.loc[worst, "failure_rate_percent"]:.2f}%).')
