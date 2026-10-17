# Bug Bounty - JavaScript
A practical collection of JavaScript reconnaissance techniques, search queries, and research methods for discovering publicly exposed client-side information during authorized bug bounty programs.

---

# JavaScript File Discovery
## Basic JavaScript Files
site:example.com filetype:js

## JavaScript Resources
site:example.com (javascript OR js)

## Static JavaScript Assets
site:example.com (static OR assets OR js)

---

# JavaScript Endpoint Discovery
## API References
site:example.com filetype:js (api OR endpoint)

## URL References
site:example.com filetype:js ("http://" OR "https://")

## Route References
site:example.com filetype:js (route OR routes OR path)

## AJAX References
site:example.com filetype:js (ajax OR fetch OR XMLHttpRequest)

---

# JavaScript Technology Discovery
## Framework Detection
site:example.com filetype:js (React OR Angular OR Vue)

## Library Detection
site:example.com filetype:js (jQuery OR lodash OR webpack)

## Frontend Assets
site:example.com filetype:js (bundle OR chunk OR assets)

---

# JavaScript Configuration Discovery
## Configuration Files
site:example.com filetype:js (config OR configuration)

## Environment References
site:example.com filetype:js (environment OR env)

## Settings References
site:example.com filetype:js (settings OR options)

---

# JavaScript API Information
## API URLs
site:example.com filetype:js ("/api/" OR "api.")

## API Versions
site:example.com filetype:js ("/v1/" OR "/v2/" OR "/v3/")

## GraphQL References
site:example.com filetype:js graphql

## Backend References
site:example.com filetype:js (backend OR server)

---

# JavaScript Parameter Discovery
## Parameters
site:example.com filetype:js (param OR parameter)

## Query Parameters
site:example.com filetype:js ("?" OR "&")

## User Parameters
site:example.com filetype:js (user OR username OR account)

## ID Parameters
site:example.com filetype:js (id OR user_id OR account_id)

---

# JavaScript Authentication References
## Login Functions
site:example.com filetype:js (login OR signin OR authenticate)

## Token References
site:example.com filetype:js (token OR access_token OR bearer)

## Session References
site:example.com filetype:js (session OR cookie)

## OAuth References
site:example.com filetype:js (oauth OR OAuth)

---

# JavaScript Source Map Discovery
## Source Maps
site:example.com filetype:map

## JavaScript Maps
site:example.com (sourceMappingURL OR sourcemap)

## Source References
site:example.com filetype:js "sourceMappingURL"

---

# JavaScript Repository Discovery
## GitHub References
"example.com" site:github.com

## GitLab References
"example.com" site:gitlab.com

## Code References
"example.com" (github OR gitlab OR repository)

---

# JavaScript File Types
Common JavaScript resources:
- main.js
- app.js
- bundle.js
- vendor.js
- runtime.js
- chunk.js
- scripts.js
- config.js

---

# JavaScript Recon Workflow
## Phase 1 - Collection
1. Identify JavaScript files.
2. Collect public scripts.
3. Organize files by application.
4. Identify source maps.

## Phase 2 - Analysis
Review for:
- API endpoints
- Routes
- Parameters
- Application logic
- Technology information
- Public configuration data

## Phase 3 - Mapping
Create an inventory:
- JavaScript file
- Related application
- Discovered endpoints
- Parameters
- Technologies
- Notes

## Phase 4 - Validation
1. Confirm ownership.
2. Confirm scope.
3. Verify discovered information.
4. Perform security testing only when authorized.

---

# JavaScript Documentation Template
| Field | Description |
|---|---|
| File | JavaScript file URL |
| Application | Related application |
| Technology | Framework or library |
| Endpoints | Discovered routes |
| Parameters | Discovered inputs |
| Source | Discovery method |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# Security Research Areas
JavaScript analysis can help identify:
- Exposed Endpoints
- Hidden Routes
- Client-Side Logic
- Information Disclosure
- Configuration Issues
- Authentication Flows
- API Communication Patterns

The presence of information inside JavaScript does not automatically mean a vulnerability exists.

---

# Important Notes
- Public JavaScript files are often intentionally accessible.
- Client-side code should be considered public information.
- Do not extract or misuse sensitive information.
- Do not attempt unauthorized access using discovered information.
- Verify scope before testing.
- Respect application owners and users.
- Follow bug bounty program rules.

---

# Responsible Research
JavaScript reconnaissance helps researchers understand how modern web applications communicate with backend services.
Use discovered information only for authorized security research and responsible disclosure.