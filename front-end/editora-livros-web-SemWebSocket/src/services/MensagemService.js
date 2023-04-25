import {Axios} from "./Axios";

const url = "/mensagem";

export const apiMensagens = {
    getMensagensLivro: async (isbn) => {
        try {
            const response = await Axios.get(url + "/" + isbn);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    postMensagem: async (mensagem) => {
        try {
            const response = await Axios.post(url, mensagem);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    }
};