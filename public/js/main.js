'use strict';

// ── Modal ────────────────────────────────────────────────────────────────────
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('open');
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('open');
}

// Close modal on overlay click
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.remove('open');
  }
});

// Close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(el => el.classList.remove('open'));
    document.querySelectorAll('.row-dropdown.open').forEach(el => el.classList.remove('open'));
    const um = document.getElementById('userMenuBtn');
    if (um) um.classList.remove('open');
  }
});

// ── User Menu ────────────────────────────────────────────────────────────────
const userMenuBtn = document.getElementById('userMenuBtn');
if (userMenuBtn) {
  userMenuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    userMenuBtn.classList.toggle('open');
  });
  document.addEventListener('click', () => userMenuBtn.classList.remove('open'));
}

// ── Row Menus ────────────────────────────────────────────────────────────────
function toggleRowMenu(id) {
  const menu = document.getElementById('rowMenu' + id);
  if (!menu) return;
  const isOpen = menu.classList.contains('open');
  document.querySelectorAll('.row-dropdown.open').forEach(el => el.classList.remove('open'));
  if (!isOpen) menu.classList.add('open');
  event.stopPropagation();
}
document.addEventListener('click', () => {
  document.querySelectorAll('.row-dropdown.open').forEach(el => el.classList.remove('open'));
});

// ── Flash auto-dismiss ────────────────────────────────────────────────────────
document.querySelectorAll('.alert').forEach(el => {
  if (!el.closest('.pat-reveal')) {
    setTimeout(() => { el.style.transition = 'opacity 0.5s'; el.style.opacity = '0'; setTimeout(() => el.remove(), 500); }, 6000);
  }
});
