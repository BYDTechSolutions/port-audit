/** The package version. Kept equal to package.json by a test. */
export const VERSION = '0.1.2';

/** The repository, named in the `User-Agent` so whoever reads the logs can see what is calling. */
export const REPO_URL = 'https://github.com/BYDTechSolutions/port-audit';

/** The `User-Agent` sent with every request. */
export const USER_AGENT = `port-audit/${VERSION} (+${REPO_URL})`;
