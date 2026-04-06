# 🛡️ Aegis-Agent: Stateless AI Identity & Secure GitHub Auth

**Aegis-Agent** is a zero-trust AI assistant that performs real GitHub repository management without ever storing a persistent API token. By leveraging **RFC 8693 (Token Exchange)** and the **Auth0 Token Vault**, Aegis-Agent ensures that user credentials never touch a database.

> **Security Philosophy:** $\text{State}(\text{Backend}) = \emptyset$
> Our backend has zero memory of your identity. Credentials exist only in volatile RAM for the duration of a single request.

---

## 🚀 Features
* **Natural Language Repository Management:** Fetch issues, summarize PRs, and check repo status using Gemini 1.5 Flash.
* **Stateless Architecture:** No database, no "forever keys," and no risk of identity breach.
* **Federated Identity:** Uses Auth0 Token Vault to securely exchange user sessions for short-lived, scoped GitHub tokens.
* **Zero-Trust Model:** Tokens are purged from memory immediately after the API call is completed.

## 🛠️ Tech Stack
* **AI Engine:** Gemini 1.5 Flash
* **Backend:** Python + FastAPI
* **Identity:** Auth0 (Implementing RFC 8693)
* **API:** GitHub REST API

---

## 🏗️ Technical Architecture: The Stateless Handshake

Aegis-Agent implements the **OAuth 2.0 Token Exchange** protocol to maintain a stateless environment:

1. **Subject Token ($T_{sub}$):** The user authenticates via Auth0, receiving a standard session token.
2. **Token Exchange:** The backend requests a scoped GitHub token from the Auth0 Token Vault.
3. **Actor Token ($T_{act}$):** Auth0 performs the exchange:
   $$f(T_{sub}, \text{Scope}) \rightarrow T_{act}$$
4. **Execution:** Gemini parses the user's intent, the backend calls the GitHub API with $T_{act}$, and the token is then **immediately discarded**.

---

## 💻 Getting Started

### Prerequisites
* Python 3.9+
* Auth0 Tenant with **Token Vault** enabled
* Gemini API Key

### Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/](https://github.com/)[your-username]/aegis-agent.git
   cd aegis-agent
