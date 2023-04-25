import React, {Component} from 'react'
import {BsFacebook, BsInstagram, BsTwitter, BsGithub, BsDribbble} from 'react-icons/bs'
import {Footer} from 'flowbite-react'

export const Rodape = () => {
    return (
        <>
            <Footer className="fixed bottom-0 h-20" container={true}>
                <div className="w-full sm:flex sm:items-center sm:justify-between">
                    <Footer.Copyright
                        href="#/"
                        by="Editora de Livros"
                        year={new Date().getFullYear()}
                    />
                    <div className="mt-6 flex space-x-6 sm:mt-0 sm:justify-center">
                        <Footer.Icon
                            href="#"
                            icon={BsFacebook}
                        />
                        <Footer.Icon
                            href="#"
                            icon={BsInstagram}
                        />
                        <Footer.Icon
                            href="#"
                            icon={BsTwitter}
                        />
                        <Footer.Icon
                            href="#"
                            icon={BsGithub}
                        />
                        <Footer.Icon
                            href="#"
                            icon={BsDribbble}
                        />
                    </div>
                </div>
            </Footer>
        </>
    )
}