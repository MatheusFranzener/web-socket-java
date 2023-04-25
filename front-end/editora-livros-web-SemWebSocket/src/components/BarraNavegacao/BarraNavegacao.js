import React, {useState} from "react";
import {Navbar, Dropdown, Avatar, Button} from "flowbite-react";
import {BookOpenIcon} from "@heroicons/react/24/outline";
import {Titulo} from "../Titulo";

export const BarraNavegacao = () => {

    const [user, setUser] = useState({
        nome: '', email: ''
    })
    const [logado, setLogado] = useState(false)


    return (<>
        <Navbar
            fluid={true}
            rounded={true}>
            <Navbar.Brand href="http://localhost:3000/">
                <BookOpenIcon className="mr-6 h-6 sm:h-9"/>
                {/*<span className="self-center whitespace-nowrap text-xl font-semibold dark:text-white">*/}
                {/*        Editora de Livros*/}
                    {/*</span>*/}
                <Titulo texto={"Editora de Livros"}/>
            </Navbar.Brand>
            {logado ? (<div className="flex md:order-2">
                <Dropdown
                    arrowIcon={false}
                    inline={true}
                    label={<Avatar alt="User settings"
                                   img="https://flowbite.com/docs/images/people/profile-picture-5.jpg"
                                   rounded={true}/>}>
                    <Dropdown.Header>
                <span className="block text-sm">
                  {user.nome}
                </span>
                        <span className="block truncate text-sm font-medium">
                  {user.email}
                </span>
                    </Dropdown.Header>
                    <Dropdown.Item>
                        Perfil
                    </Dropdown.Item>
                    <Dropdown.Divider/>
                    <Dropdown.Item>
                        Logout
                    </Dropdown.Item>
                </Dropdown>
                <Navbar.Toggle/>
            </div>) : (<div className="flex md:order-2">
                <Button href="/usuario/cadastro">
                    Cadastro
                </Button>
                <Button href="/login">
                    Login
                </Button>
            </div>)}
            <Navbar.Collapse>
                <Navbar.Link href="/" active={true}>
                    Home
                </Navbar.Link>
                <Navbar.Link href="/livros">
                    Livros
                </Navbar.Link>
                <Navbar.Link href="/contato">
                    Contato
                </Navbar.Link>
            </Navbar.Collapse>
        </Navbar>
    </>)
}