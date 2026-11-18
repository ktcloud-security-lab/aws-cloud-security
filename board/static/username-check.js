document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('auth-form');
  const input = document.getElementById('username');
  const button = document.getElementById('check-username');
  const message = document.getElementById('username-message');
  if (!form || !input || !button || !message) return;

  let checkedName = null;
  let version = 0;
  let pending = null;
  function show(text, success = false) {
    message.textContent = text;
    message.style.color = success ? '#16803c' : '#c2410c';
  }
  input.addEventListener('input', () => {
    version += 1;
    checkedName = null;
    if (pending) pending.abort();
    button.disabled = false;
    show('아이디 중복 확인을 해 주세요.');
  });
  button.addEventListener('click', async () => {
    const name = input.value.trim();
    checkedName = null;
    if (!name || Array.from(name).length > 30) {
      show('아이디를 1~30자로 입력해 주세요.');
      input.focus();
      return;
    }
    const currentVersion = ++version;
    const controller = new AbortController();
    pending = controller;
    const timeout = setTimeout(() => controller.abort(), 10000);
    button.disabled = true;
    show('확인 중입니다…');
    try {
      const response = await fetch(button.dataset.url, {
        method: 'POST', credentials: 'same-origin', signal: controller.signal,
        body: new URLSearchParams({username: name,
          csrf_token: form.elements.namedItem('csrf_token').value})
      });
      const data = await response.json();
      if (currentVersion !== version) return;
      if (!response.ok) throw new Error('Lookup failed');
      if (data.available === true) checkedName = name;
      show(data.message, data.available === true);
    } catch (error) {
      if (currentVersion === version) {
        show('확인에 실패했습니다. 페이지를 새로고침하거나 잠시 후 다시 시도해 주세요.');
      }
    } finally {
      clearTimeout(timeout);
      if (currentVersion === version) {
        button.disabled = false;
        pending = null;
      }
    }
  });
  form.addEventListener('submit', event => {
    if (checkedName !== input.value.trim()) {
      event.preventDefault();
      show('회원가입 전에 아이디 중복 확인을 해 주세요.');
      button.focus();
    }
  });
});
