import html from './login-form-component.html?raw';
import css from './login-form-component.css?raw';

const tpl = document.createElement('template');

tpl.innerHTML = `
  <style>${css}</style>
  ${html}
`;

class LoginForm extends HTMLElement {
    private shadow = this.attachShadow({mode: "open"});
    private form: HTMLFormElement | null = null;
    public onSubmit?: (username: string, password: string) => void | Promise<void>;

    private handleSubmit = async (event: SubmitEvent) => {
        event.preventDefault();

        const form = event.target as HTMLFormElement | null;
        if (!form) {
            return;
        }

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
                redirect: 'follow',
            });

            if (response.redirected) {
                window.location.href = response.url;
                return;
            }

            if (!response.ok) {
                const message = await response.text();
                console.error('login failed', response.status, message);
            }
        } catch (error) {
            console.error('login request failed', error);
        }
    };

    connectedCallback() {
        if (!this.shadow.hasChildNodes()) {
            this.shadow.appendChild(tpl.content.cloneNode(true));
        }

        this.form = this.shadow.querySelector('form');
        if (!this.form) {
            console.error('no form');
        }
        this.form?.addEventListener('submit', this.handleSubmit);
    }

    disconnectedCallback() {
        this.form?.removeEventListener('submit', this.handleSubmit);
        this.form = null;
    }
}



customElements.define("login-form", LoginForm);
