// Tailwind build for the utility classes the markup still uses (v3.4.19, the latest 3.x;
// the former browser runtime was 3.4.17). Regenerate after changing markup:
//   bash .github/scripts/build-utilities-css.sh
// Class names that the scripts assemble at runtime (for example
// bg-${color}-100) cannot be found by scanning, so they go in the safelist.
module.exports = {
    darkMode: 'class',
    // A hover style applies only where a pointer can hover, so a tapped control
    // does not stay highlighted on a touch screen (as in ui.css)
    future: { hoverOnlyWhenSupported: true },
    content: ['./frontend/*.html', './frontend/*.js'],
    theme: { extend: {} },
    safelist: [],
};
