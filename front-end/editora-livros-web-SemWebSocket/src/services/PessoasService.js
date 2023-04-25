import axios from "axios";

const url = "/pessoa";
// const url = "http://localhost:8080/editora-livros-api/pessoa";

class PessoasService {

    config = {
        withCredentials: true,
    };

    postAutor(pessoa) {
        return axios.post(url, pessoa, this.config);
    }

    postRevisor(pessoa) {
        return axios.post(url + "/revisor", pessoa, this.config);
    }

    getGeneros() {
        return axios.get(url + "/generos", this.config);
    }

    getPessoa(cpf) {
        return axios.get(url + "/" + cpf, this.config);
    }

    deletePessoa(cpf) {
        return axios.delete(url + "/" + cpf, this.config);
    }

    putPessoa(cpf , pessoa) {
        return axios.put(url + "/" + cpf, pessoa, this.config);
    }

    getUsuarioLogado() {
        return axios.get(url + "/logado", this.config);
    }
}

export default PessoasService;