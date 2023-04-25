import {Axios} from "./Axios";
// import {useNavigate} from "react-router-dom";

// const url = "http://editorasenaiapi:8080/editora-livros-api/livro";
const url = "/livro";

//
// export const postLivro = async (livro) => {
//     return await Axios.post(url, livro)
//         .catch(error => {
//             console.log(error);
//         });
// }
//
// export const getLivros = async () => {
//     return await Axios.get(url)
//         .then(response => {
//             return response;
//         })
//         .catch(error => {
//             console.log(error);
//         });
// }
//
// export const getStatus = async () => {
//     return await Axios.get(url + "/status");
// }
//
// export const getLivrosPesquisa = async (pesquisa) => {
//     return await Axios.get(url + "/" + pesquisa);
// }
//
// export const getLivro = async (isbn) => {
//     return await Axios.get(url + "/isbn/" + isbn);
// }
//
// export const deleteLivro = async (isbn) => {
//     return await Axios.delete(url + "/" + isbn);
// }
//
// export const putLivro = async (isbn, livro) => {
//     return await Axios.put(url + "/" + isbn, livro);
// }



export const apiLivros = {
    getLivros: async () => {
        try {
            const response = await Axios.get(url);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    getLivrosPesquisa: async (pesquisa) => {
        try {
            const response = await Axios.get(url + `/${pesquisa}`);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    getLivro: async (isbn) => {
        try {
            const response = await Axios.get(url + `/isbn/${isbn}`);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    postLivro: async (livro) => {
        try {
            const response = await Axios.post(url, livro);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    putLivro: async (isbn, livro) => {
        try {
            const response = await Axios.put(url + `/isbn/${isbn}`, livro);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    deleteLivro: async (isbn) => {
        try {
            const response = await Axios.delete(url + `/${isbn}`);
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },

    getStatus: async () => {
        try {
            const response = await Axios.get(url + "/status");
            return response.data;
        } catch (error) {
            console.log(error);
            throw error;
        }
    },
};