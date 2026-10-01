document.addEventListener("DOMContentLoaded", () => {
    initialiseEvidenceViewer();
    initialiseNotesForm();
    initialiseConfirmButtons();
});


function initialiseEvidenceViewer() {
    const searchInput = document.getElementById(
        "evidence-search"
    );

    const evidenceContent = document.getElementById(
        "evidence-content"
    );

    const resultCounter = document.getElementById(
        "search-result-count"
    );

    const wrapButton = document.getElementById(
        "toggle-wrap"
    );

    if (!evidenceContent) {
        return;
    }

    const lineElements = Array.from(
        evidenceContent.querySelectorAll(
            ".line-content"
        )
    );

    const lineRows = Array.from(
        evidenceContent.querySelectorAll(
            ".evidence-line"
        )
    );

    const originalLines = lineElements.map(
        (element) => {
            return element.dataset.original
                ?? element.textContent
                ?? "";
        }
    );


    function escapeHtml(value) {
        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function escapeRegularExpression(value) {
        return String(value).replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&"
        );
    }


    function protectMatches(
        value,
        expression,
        className,
        tokens
    ) {
        return value.replace(
            expression,
            (match) => {
                const tokenIndex = tokens.length;

                tokens.push(
                    `<span class="${className}">${match}</span>`
                );

                return `\uE000${tokenIndex}\uE001`;
            }
        );
    }


    function restoreProtectedTokens(
        value,
        tokens
    ) {
        return value.replace(
            /\uE000(\d+)\uE001/g,
            (placeholder, tokenIndex) => {
                return tokens[
                    Number(tokenIndex)
                ] ?? placeholder;
            }
        );
    }


    function applySyntaxHighlighting(
        originalText
    ) {
        let highlightedText = escapeHtml(
            originalText
        );

        const protectedTokens = [];

        /*
         * Order matters.
         *
         * URLs are protected before domains and IP addresses so
         * sections of a URL are not highlighted more than once.
         */

        const urlExpression =
            /\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi;

        const timestampExpression =
            /\b(?:\d{4}[-/.]\d{2}[-/.]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?|\d{2}[-/.]\d{2}[-/.]\d{4}\s+\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\b/g;

        const hashExpression =
            /\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b/g;

        const ipv4Expression =
            /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

        const ipv6Expression =
            /\b(?:(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}|::1)\b/g;

        const domainExpression =
            /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:local|internal|test|example|invalid|localhost|com|net|org|io|co|in|edu|gov|mil|biz|info|xyz|site|online|cloud|dev|app|me|uk|us|ru|cn|de|fr|jp|au|ca)\b/gi;

        const criticalExpression =
            /\bCRITICAL\b/gi;

        const errorExpression =
            /\b(?:ERROR|ERR|FAILED|FAILURE)\b/gi;

        const warningExpression =
            /\b(?:WARNING|WARN)\b/gi;

        const infoExpression =
            /\bINFO\b/gi;


        highlightedText = protectMatches(
            highlightedText,
            urlExpression,
            "evidence-token evidence-token-url",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            timestampExpression,
            "evidence-token evidence-token-timestamp",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            hashExpression,
            "evidence-token evidence-token-hash",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            ipv4Expression,
            "evidence-token evidence-token-ip",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            ipv6Expression,
            "evidence-token evidence-token-ip",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            domainExpression,
            "evidence-token evidence-token-domain",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            criticalExpression,
            "evidence-token evidence-token-critical",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            errorExpression,
            "evidence-token evidence-token-error",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            warningExpression,
            "evidence-token evidence-token-warning",
            protectedTokens
        );

        highlightedText = protectMatches(
            highlightedText,
            infoExpression,
            "evidence-token evidence-token-info",
            protectedTokens
        );

        return restoreProtectedTokens(
            highlightedText,
            protectedTokens
        );
    }


    function highlightSearchTerm(
        highlightedHtml,
        originalText,
        searchTerm
    ) {
        if (!searchTerm) {
            return {
                html: highlightedHtml,
                matches: 0,
            };
        }

        const searchExpression = new RegExp(
            escapeRegularExpression(
                searchTerm
            ),
            "gi"
        );

        const matches = originalText.match(
            searchExpression
        );

        if (!matches) {
            return {
                html: highlightedHtml,
                matches: 0,
            };
        }

        /*
         * Search highlighting is applied only to visible text
         * nodes so it does not damage syntax-highlight classes.
         */

        const temporaryContainer =
            document.createElement("span");

        temporaryContainer.innerHTML =
            highlightedHtml;

        const treeWalker =
            document.createTreeWalker(
                temporaryContainer,
                NodeFilter.SHOW_TEXT
            );

        const textNodes = [];

        while (treeWalker.nextNode()) {
            textNodes.push(
                treeWalker.currentNode
            );
        }

        textNodes.forEach((textNode) => {
            const textValue =
                textNode.nodeValue ?? "";

            if (!searchExpression.test(textValue)) {
                searchExpression.lastIndex = 0;
                return;
            }

            searchExpression.lastIndex = 0;

            const replacementFragment =
                document.createDocumentFragment();

            let previousIndex = 0;

            textValue.replace(
                searchExpression,
                (matchedValue, matchIndex) => {
                    replacementFragment.appendChild(
                        document.createTextNode(
                            textValue.slice(
                                previousIndex,
                                matchIndex
                            )
                        )
                    );

                    const markElement =
                        document.createElement(
                            "mark"
                        );

                    markElement.textContent =
                        matchedValue;

                    replacementFragment.appendChild(
                        markElement
                    );

                    previousIndex =
                        matchIndex
                        + matchedValue.length;

                    return matchedValue;
                }
            );

            replacementFragment.appendChild(
                document.createTextNode(
                    textValue.slice(
                        previousIndex
                    )
                )
            );

            textNode.parentNode.replaceChild(
                replacementFragment,
                textNode
            );
        });

        return {
            html: temporaryContainer.innerHTML,
            matches: matches.length,
        };
    }


    function renderEvidenceLines(
        searchTerm = ""
    ) {
        let totalMatches = 0;

        lineElements.forEach(
            (element, index) => {
                const originalText =
                    originalLines[index];

                const syntaxHighlighted =
                    applySyntaxHighlighting(
                        originalText
                    );

                const searchResult =
                    highlightSearchTerm(
                        syntaxHighlighted,
                        originalText,
                        searchTerm
                    );

                element.innerHTML =
                    searchResult.html;

                totalMatches +=
                    searchResult.matches;

                const row = lineRows[index];

                if (row) {
                    row.classList.toggle(
                        "matching-line",
                        searchResult.matches > 0
                    );
                }
            }
        );

        if (!resultCounter) {
            return;
        }

        if (!searchTerm) {
            resultCounter.textContent =
                "No search active";
        } else if (totalMatches === 1) {
            resultCounter.textContent =
                "1 match";
        } else {
            resultCounter.textContent =
                `${totalMatches} matches`;
        }
    }


    function updateSearch() {
        const searchTerm = searchInput
            ? searchInput.value.trim()
            : "";

        renderEvidenceLines(
            searchTerm
        );
    }


    /*
     * Run syntax highlighting immediately when the viewer opens.
     */
    renderEvidenceLines();


    if (searchInput) {
        searchInput.addEventListener(
            "input",
            updateSearch
        );

        document.addEventListener(
            "keydown",
            (event) => {
                const activeElement =
                    document.activeElement;

                const editingText =
                    activeElement
                    && (
                        activeElement.tagName === "INPUT"
                        || activeElement.tagName === "TEXTAREA"
                        || activeElement.tagName === "SELECT"
                        || activeElement.isContentEditable
                    );

                if (
                    event.key === "/"
                    && !editingText
                ) {
                    event.preventDefault();

                    searchInput.focus();
                    searchInput.select();
                }

                if (
                    event.key === "Escape"
                    && document.activeElement
                        === searchInput
                ) {
                    searchInput.value = "";

                    updateSearch();

                    searchInput.blur();
                }
            }
        );
    }


    if (wrapButton) {
        wrapButton.addEventListener(
            "click",
            () => {
                const wordWrapEnabled =
                    evidenceContent.classList.toggle(
                        "word-wrap"
                    );

                wrapButton.textContent =
                    wordWrapEnabled
                        ? "Word Wrap: On"
                        : "Word Wrap: Off";

                wrapButton.setAttribute(
                    "aria-pressed",
                    String(wordWrapEnabled)
                );
            }
        );
    }
}


function initialiseNotesForm() {
    const notesForm = document.getElementById(
        "notes-form"
    );

    const saveStatus = document.getElementById(
        "note-save-status"
    );

    if (!notesForm) {
        return;
    }

    notesForm.addEventListener(
        "submit",
        async (event) => {
            event.preventDefault();

            const submitButton =
                notesForm.querySelector(
                    'button[type="submit"]'
                );

            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent =
                    "Saving...";
            }

            if (saveStatus) {
                saveStatus.textContent =
                    "Saving notes...";
            }

            try {
                const response = await fetch(
                    notesForm.action,
                    {
                        method: "POST",
                        body: new FormData(
                            notesForm
                        ),
                        headers: {
                            "X-Requested-With":
                                "XMLHttpRequest",
                        },
                    }
                );

                if (!response.ok) {
                    throw new Error(
                        "Unable to save notes."
                    );
                }

                const result =
                    await response.json();

                if (saveStatus) {
                    saveStatus.textContent =
                        `Saved: ${result.updated_at}`;
                }

            } catch (error) {
                if (saveStatus) {
                    saveStatus.textContent =
                        "Save failed. Try again.";
                }

            } finally {
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.textContent =
                        "Save Notes";
                }
            }
        }
    );
}


function initialiseConfirmButtons() {
    const confirmButtons =
        document.querySelectorAll(
            "[data-confirm]"
        );

    confirmButtons.forEach((button) => {
        button.addEventListener(
            "click",
            (event) => {
                const message =
                    button.dataset.confirm
                    || "Continue?";

                if (!window.confirm(message)) {
                    event.preventDefault();
                }
            }
        );
    });
}
