import html from './login-form-component.html?raw';
import css from './login-form-component.css?raw';

const tpl = document.createElement('template');

tpl.innerHTML = `
  <style>${css}</style>
  ${html}
`;

type LoginResponse = {
    redirect_url?: string;
    message?: string;
};

type AuthorizationNextResponse = {
    grant_type: string;
    next_security_tool?: string;
    redirect_url?: string;
    completed: boolean;
    message?: string;
};

class LoginForm extends HTMLElement {
    private shadow = this.attachShadow({mode: "open"});
    private form: HTMLFormElement | null = null;
    private errorElement: HTMLDivElement | null = null;
    public onSubmit?: (username: string, password: string) => void | Promise<void>;

    private handleSubmit = async (event: SubmitEvent) => {
        event.preventDefault();

        const form = event.target as HTMLFormElement | null;
        if (!form) {
            return;
        }

        this.setError();

        const formData = new FormData(form);
        const username = formData.get('username');
        const password = formData.get('password');

        if (typeof username !== 'string' || typeof password !== 'string') {
            console.error('login form missing credentials');
            return;
        }

        if (typeof this.onSubmit === 'function') {
            await this.onSubmit(username, password);
            return;
        }

        await this.submitLogin(username, password);
    };

    private submitLogin = async (username: string, password: string) => {
        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include',
            });

            const payload = await this.parseJSON<LoginResponse>(response);

            if (!response.ok) {
                const message = payload?.message || `Login failed (${response.status})`;
                this.setError(message);
                return;
            }

            const nextUrl = payload?.redirect_url || '/auth/authorize/next';
            await this.advanceAuthorizationFlow(nextUrl);
        } catch (error) {
            console.error('login request failed', error);
            this.setError('Unable to reach login service');
        }
    };

    private advanceAuthorizationFlow = async (endpoint: string) => {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({}),
                credentials: 'include',
            });

            const payload = await this.parseJSON<AuthorizationNextResponse>(response);

            if (!response.ok || !payload) {
                const message =
                    payload?.message ||
                    `Authorization failed (${response.status})`;
                this.setError(message);
                return;
            }

            if (payload.completed) {
                if (payload.redirect_url) {
                    window.location.href = payload.redirect_url;
                    return;
                }

                this.setError('Authorization completed but no redirect URL provided');
                return;
            }

            const nextTool = payload.next_security_tool;
            if (nextTool === 'LOGIN_FORM') {
                // Stay on login form; nothing else to do.
                return;
            }

            this.setError(`Unsupported security tool: ${nextTool ?? 'unknown'}`);
        } catch (error) {
            console.error('authorize/next request failed', error);
            this.setError('Unable to continue authorization');
        }
    };

    private setError(message?: string) {
        if (!this.errorElement) {
            return;
        }

        if (!message) {
            this.errorElement.textContent = '';
            this.errorElement.setAttribute('hidden', '');
            return;
        }

        this.errorElement.textContent = message;
        this.errorElement.removeAttribute('hidden');
    }

    private async parseJSON<T>(response: Response): Promise<T | null> {
        try {
            return (await response.clone().json()) as T;
        } catch {
            return null;
        }
    }

    connectedCallback() {
        if (!this.shadow.hasChildNodes()) {
            this.shadow.appendChild(tpl.content.cloneNode(true));
        }

        this.form = this.shadow.querySelector('form');
        if (!this.form) {
            console.error('no form');
        }
        this.form?.addEventListener('submit', this.handleSubmit);

        this.errorElement = this.shadow.querySelector('.error');
    }

    disconnectedCallback() {
        this.form?.removeEventListener('submit', this.handleSubmit);
        this.form = null;
        this.errorElement = null;
    }
}



customElements.define("login-form", LoginForm);
