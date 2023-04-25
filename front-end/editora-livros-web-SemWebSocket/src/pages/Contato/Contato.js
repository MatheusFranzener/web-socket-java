import React from 'react'
import {Label, TextInput, Textarea, Card, Button} from 'flowbite-react'
// import {Card, Button} from "@mui/material";
import ForwardToInboxIcon from '@mui/icons-material/ForwardToInbox';
// import {PaperAirplaneIcon} from '@heroicons/react/24/outline'
import {Titulo} from "../../components";

export const Contato = () => {
    return (
        <>
            <Card>
                <form className="space-y-2" action="src/components#">
                    <Titulo texto={"Envie-nos uma mensagem"}/>
                    <div>
                        <Label
                            htmlFor="email"
                            value="Informe o seu email"
                        />
                        <TextInput
                            id="email"
                            type="email"
                            placeholder="usuario@dominio.com"
                            required={true}
                        />
                    </div>
                    <div>
                        <Label
                            htmlFor="assunto"
                            value="Assunto"
                        />
                        <TextInput
                            id="assunto"
                            type="text"
                            placeholder="Dê um assunto para a sua mensagem"
                            required={true}
                        />
                    </div>
                    <div>
                        <Label
                            htmlFor="mensagem"
                            value="Mensagem"
                        />
                        <Textarea
                            id="mensagem"
                            placeholder="Digite a sua mensagem aqui..."
                            required={true}
                            rows={3}
                        />
                    </div>
                        <Button type="submit">
                    <ForwardToInboxIcon className='h-4 w-auto pr-2'/>
                    {/*<Button variant="outlined" endIcon={<ForwardToInboxIcon />} type="submit">*/}
                        Enviar mensagem
                    </Button>
                </form>
            </Card>
        </>
    )
}