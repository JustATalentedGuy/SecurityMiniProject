export class ApiError extends Error {
  constructor(data, status) {
    super(data.message || "The request could not be completed.");
    this.code = data.error;
    this.requestId = data.request_id;
    this.status = status;
  }
}

export async function api(
  path,
  {
    method = "GET",
    data,
    token,
    headers = {},
    binary = false,
    body,
    signal,
  } = {},
) {
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers: {
      ...(data ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: data ? JSON.stringify(data) : body,
    signal,
  });
  if (!response.ok) {
    let error;
    try {
      error = await response.json();
    } catch {
      error = { message: `Server returned HTTP ${response.status}.` };
    }
    throw new ApiError(error, response.status);
  }
  if (response.status === 204) return null;
  return binary
    ? new Uint8Array(await response.arrayBuffer())
    : response.json();
}
