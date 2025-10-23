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
    public onSubmit?: (username: string, password: string) => void;

    private handleSubmit = (event: Event) => {
        event.preventDefault();

        const form = event.target as HTMLFormElement | null;
        if (!form) {
            return;
        }

        const formData = new FormData(form);
        const username = (formData.get('username')) as string;
        const password = (formData.get('password')) as string;

        if (typeof this.onSubmit === 'function') {
            this.onSubmit(username, password);
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
