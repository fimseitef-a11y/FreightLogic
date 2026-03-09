# Repository Structure

## PWA Folder Structure
- **/src**: Contains all the source code for the application.
  - **/components**: Contains reusable React components.
  - **/pages**: Contains page components that are used in routing.
  - **/services**: Contains logic for interacting with APIs and managing state.
  - **/assets**: Contains images, stylesheets, and other static assets.

## File Organization
- Each component in **/components** should have its own folder and may include:
  - A `.js` file for the component logic.
  - A `.css` file for styles (if applicable).
  - A `test.js` file for component testing.

- Each page in **/pages** follows a similar structure to components.

- Services in **/services** typically include a single file per API.

- Assets in **/assets** are organized by type (e.g., images, styles).

## Finding Components
- Components can be found under the **/components** directory.
- Pages are located under **/pages**.
- Any API service that the application interacts with is located in the **/services** folder.
- Static assets can be found in **/assets**.

This structure is designed to promote cleanliness and maintainability within the codebase. Each folder serves a specific purpose and follows best practices for organizing files in a project.