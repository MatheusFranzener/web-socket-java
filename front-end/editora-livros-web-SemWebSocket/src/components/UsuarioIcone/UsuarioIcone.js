import {Avatar} from 'flowbite-react';
import React from 'react';

export const UsuarioIcone = ({pessoa}) => {
    return (
        <Avatar
            img="https://flowbite.com/docs/images/people/profile-picture-5.jpg"
            rounded={true}
            status={pessoa.statuschat.status}
            statusPosition="bottom-right"
        />
    );
}