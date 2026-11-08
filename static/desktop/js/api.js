/** 极简 fetch 封装：同源 Cookie 认证，错误统一抛出带 status 的 Error。 */

async function request(method, path, body) {
  const options = {
    method,
    credentials: "same-origin",
    headers: {},
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    // 204 / 非 JSON 响应（例如网关错误页）不应让调用方拿到 null 却以为成功
  }
  if (!response.ok) {
    const detail = data && data.detail ? data.detail : `请求失败（HTTP ${response.status}）`;
    const error = new Error(String(detail));
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

export const api = {
  get: (path) => request("GET", path),
  post: (path, body) => request("POST", path, body),
  put: (path, body) => request("PUT", path, body),
};
