import React, {useEffect, useState} from "react";
import {Button, Card, Label, TextInput, Checkbox, Select, Spinner} from "flowbite-react";
import PessoasService from "../../services/PessoasService";
import pessoaJson from "./pessoa.json";
import { Navigate } from 'react-router-dom';

export const CadastroUsuario = () => {

    const [confSenha, setConfSenha] = useState(null)
    const [pessoa, setPessoa] = useState(pessoaJson)
    const [carregando, setCarregando] = useState(false)

    const submit = () => {
        PessoasService.postPessoa(pessoa).then(response => {
            console.log(response)
        }).catch(error => {
            console.log(error)
        })
    }

    const atualizarPessoa = (event) => {
        const { name, value } = event.target;
        setPessoa((pessoa) => ({ ...pessoa, [name]: value }));
    };

    function voltar() {
        console.log("voltar")
        return <Navigate to="/livros" />
    }

    const [listaGenero, setListaGenero] = useState([])

    useEffect(() => {
        setCarregando(true)
        PessoasService.getGeneros().then(response => {
            setListaGenero(response.data)
        }).catch(error => {
            console.log(error)
        }).finally(() => {
            setCarregando(false)
        })
    }, [])

    if (carregando) {
        return (
            <div className="flex justify-center items-center h-80">
                <Spinner/>
            </div>
        )
    }
    return (
        <>
            <Card>
                <form id='formLivro' onSubmit={submit}>
                    <div className="my-2 grid gap-2 grid-cols-2">
                        <div>
                            <Label
                                htmlFor="nome"
                                value="Nome"
                            />
                            <TextInput
                                id="nome"
                                type="text"
                                placeholder="Tony"
                                required={true}
                                name='nome'
                                value={pessoa.nome}
                                onChange={atualizarPessoa}
                            />
                        </div>
                        <div>
                            <Label
                                htmlFor="sobrenome"
                                value="Sobrenome"
                            />
                            <TextInput
                                id="sobrenome"
                                type="text"
                                placeholder="Stark"
                                required={true}
                                name='sobrenome'
                                value={pessoa.sobrenome}
                                onChange={atualizarPessoa}
                            />
                        </div>
                        <div>
                            <Label
                                htmlFor="cpf"
                                value="CPF"
                            />
                            <TextInput
                                id="cpf"
                                type="number"
                                placeholder="1234"
                                required={true}
                                name='cpf'
                                value={pessoa.cpf}
                                onChange={atualizarPessoa}
                            />
                        </div>
                        <div>
                            <Label
                                htmlFor="status"
                                value="Selecione o gênero"
                            />
                            <Select
                                id="genero"
                                required={true}
                                name="genero"
                                value={pessoa.genero}
                                onChange={atualizarPessoa}
                            >
                                {listaGenero.map((genero) => (
                                    <option key={genero}>
                                        {genero}
                                    </option>
                                ))}
                            </Select>
                        </div>
                    </div>
                    <div>
                        <Label
                            htmlFor="email"
                            value="E-mail"
                        />
                        <TextInput
                            id="email"
                            type="email"
                            placeholder="usuario@dominio.com"
                            required={true}
                            name='email'
                            value={pessoa.email}
                            onChange={atualizarPessoa}
                        />
                    </div>
                    <div className="my-2 grid gap-2 grid-cols-2">
                        <div>
                            <Label
                                htmlFor="senha"
                                value="Senha"
                            />
                            <TextInput
                                id="senha"
                                type="password"
                                placeholder="1234"
                                required={true}
                                name='senha'
                                value={pessoa.senha}
                                onChange={atualizarPessoa}
                            />
                        </div>
                        <div>
                            <Label
                                htmlFor="confSenha"
                                value="Confirmação de Senha"
                            />
                            <TextInput
                                id="confSenha"
                                type="password"
                                placeholder="1234"
                                required={true}
                                name='confSenha'
                                value={confSenha}
                                onChange={(event) => setConfSenha(event.target.value)}
                            />
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <Checkbox id="agree"/>
                        <Label htmlFor="agree">
                            Li e estou de acordo com os {' '}
                            <a
                                href="/termos"
                                className="text-blue-600 hover:underline dark:text-blue-500"
                            >
                                termos e condições
                            </a>
                        </Label>
                    </div>
                    <div className="mt-8 grid gap-10 grid-cols-2">
                        <Button type="submit">
                            Cadastrar
                        </Button>
                        <Button color="light" onClick={voltar}>
                            Voltar
                        </Button>
                    </div>
                </form>
            </Card>
        </>
    )
}