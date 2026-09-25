// SPDX-License-Identifier: AGPL-3.0-only
// Entry point of the islands bundle (loaded with defer on logged-in pages).
import { initCopy } from "./copy";
import { initCsrf } from "./csrf";
import { initFilters } from "./filter";

initCsrf();
initCopy();
initFilters();
