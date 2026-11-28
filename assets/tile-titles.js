const singleWordTitles = Array.from(document.querySelectorAll('.tile-name'))
  .filter(title => title && /^\S+$/u.test(title.textContent.trim()));

function fitSingleWordTitle(title) {
  const available = title.clientWidth;
  if (!available) return;
  title.style.fontSize = '';
  const range = document.createRange();
  range.selectNodeContents(title);
  const width = range.getBoundingClientRect().width;
  if (width > available) {
    const size = parseFloat(getComputedStyle(title).fontSize);
    title.style.fontSize = (Math.floor(size * available / width * 10) / 10) + 'px';
  }
}

const titleObserver = new ResizeObserver(entries => {
  for (const {target} of entries) fitSingleWordTitle(target);
});
for (const title of singleWordTitles) {
  title.classList.add('single-word');
  titleObserver.observe(title);
}
document.fonts.ready.then(() => singleWordTitles.forEach(fitSingleWordTitle));
