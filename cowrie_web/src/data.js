export function getApiBase() {
  const path = window.location.pathname.replace(/\/$/, '');
  return `${path}/api`;
}

export async function getStats() {
  const res = await fetch(`${getApiBase()}/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return await res.json();
}

export async function getAllSessions() {
  const res = await fetch(`${getApiBase()}/sessions`);
  if (!res.ok) throw new Error('Failed to fetch sessions');
  return await res.json();
}

export async function getSessionById(id) {
  const res = await fetch(`${getApiBase()}/sessions/${id}`);
  if (!res.ok) throw new Error('Failed to fetch session details');
  return await res.json();
}

export async function getLiveFeed() {
  const res = await fetch(`${getApiBase()}/live`);
  if (!res.ok) throw new Error('Failed to fetch live feed');
  return await res.json();
}

