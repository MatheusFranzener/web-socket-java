import {Axios} from "./Axios";

// const url = "http://editorasenaiapi:8080/login/auth";
const url = "/login/auth";
// const url = "https://localhost:8443/login";


export const login = async (user) => {
    console.log(user);
    await Axios.post(url, user)
        .catch(error => {
            console.error(error);
        });
}

// getUser() {
// Obtém o usuário logado a partir do body da resposta da API
//     return axios.get('/api/user')
//         .then(response => response.data);
// }