import React from 'react';
import {BrowserRouter, Routes, Route} from 'react-router-dom';
import {Rodape, BarraNavegacao} from './components';
import {Home, Livros, Contato, Login, CadastroUsuario, ChatRoom, CadastroLivro} from './pages';

export const App = React.memo(() => {
    return (<>
            <BrowserRouter>
                    <BarraNavegacao/>
                    <div className="container mx-auto mb-20 px-4 sm:px-6 py-6">
                        <Routes>
                            <Route path="/" element={<Home/>}/>
                            <Route path="/login" element={<Login/>}/>
                            <Route path="/contato" element={<Contato/>}/>
                            <Route path="/usuario/cadastro" element={<CadastroUsuario/>}/>
                            <Route path="/usuario/editar:cpf" element={<CadastroUsuario/>}/>
                            <Route path="/livros" element={<Livros/>}/>
                            <Route path="/livro/cadastro" element={<CadastroLivro/>}/>
                            <Route path="/livro/:isbn" element={<CadastroLivro/>}/>
                            <Route path="/livro/:isbn/chat" element={<ChatRoom/>}/>
                            <Route path="/livro/editar/:isbn" element={<CadastroLivro/>}/>
                        </Routes>
                    </div>
                    <Rodape/>
                </BrowserRouter>
        </>)
})
