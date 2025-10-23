import html from './login-form-component.html?raw';
import css from './login-form-component.css?raw';

const tpl = document.createElement('template');

tpl.innerHTML = `
  <style>${css}</style>
  ${html}
`;

class LoginForm extends HTMLElement {
    private shadow = this.attachShadow({mode: "open"});

    connectedCallback() {
        this.shadow.appendChild(tpl.content.cloneNode(true));
    }
}



customElements.define("login-form", LoginForm);
