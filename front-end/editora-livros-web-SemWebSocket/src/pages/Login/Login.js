import React, {useState} from 'react'
import {Button, Card, Checkbox, Label, TextInput} from 'flowbite-react'
import {login} from "../../services";
import GoogleIcon from '@mui/icons-material/Google';
import GitHubIcon from '@mui/icons-material/GitHub';
import FacebookIcon from '@mui/icons-material/Facebook';
import { Navigate } from 'react-router-dom';

export const Login = () => {
    const [logado, setLogado] = useState(false);
    const [user, setUser] = useState({
        email: '',
        senha: ''
    });

    const atualizarUsuario = (event) => {
        setUser({...user, [event.target.name]: event.target.value})
        console.log(user);
    }

    const handleLogin = async (e) => {
        e.preventDefault();
        await login(user).then(() => {
            setLogado(true);
        }).catch((error) => {
            console.error(error);
        })
    }

    if (logado) {
        return <Navigate to="/livros" />
    }

    return (
        <>
            <Card className="max-w-lg min-w-md mx-auto">
                <form className="flex flex-col gap-4" onSubmit={handleLogin}>
                    <div>
                        <Label
                            htmlFor="email"
                            value="E-mail"
                        />
                        <TextInput
                            id="email"
                            type="email"
                            placeholder="usuario@dominio.com"
                            name='email'
                            value={user.email}
                            required={true}
                            onChange={atualizarUsuario}
                        />
                    </div>
                    <div>
                        <Label
                            htmlFor="senha"
                            value="Senha"
                        />
                        <TextInput
                            id="senha"
                            type="password"
                            name='senha'
                            value={user.senha}
                            required={true}
                            onChange={atualizarUsuario}
                        />
                    </div>
                    <div className="flex items-center gap-2">
                        <Checkbox id="remember"/>
                        <Label htmlFor="remember">
                            Remember me
                        </Label>
                    </div>
                    <Button
                        type="submit">
                        Login
                    </Button>
                    <div className="grid gap-2 grid-cols-3">
                        <Button
                            pill={true}
                            outline={true}
                            color="failure"
                            href={"https://localhost:8443/oauth2/authorization/google"}>
                            <GoogleIcon fontSize={"large"}/>
                        </Button>
                        <Button
                            pill={true}
                            outline={true}
                            href={"https://localhost:8443/oauth2/authorization/google"}>
                            <FacebookIcon fontSize={"large"}/>
                        </Button>
                        <Button
                            pill={true}
                            outline={true}
                            color="dark"
                            href={"https://localhost:8443/oauth2/authorization/google"}>
                            <GitHubIcon fontSize={"large"}/>
                        </Button>
                    </div>
                </form>
            </Card>
        </>
    )
}