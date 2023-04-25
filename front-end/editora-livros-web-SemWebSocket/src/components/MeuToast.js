import React from 'react'
import { Toast } from 'flowbite-react'
import { HiCheck } from 'react-icons/hi'

class MeuToast extends React.Component {
    render() {
        let toastCss = {
            display: this.props.toastDados.show ? "block" : "none",
            position: "fixed",
            right: "1%",
            bottom: "15%",
        }
        return (
            <Toast style={toastCss}>
                <div className='inline-flex'>
                    <div className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-100 text-green-500 dark:bg-green-800 dark:text-green-200">
                        <HiCheck className="h-5 w-5" />
                    </div>
                    <div className="ml-3 text-sm font-normal">
                        {this.props.toastDados.mensagem}
                    </div>
                    <div>
                        <Toast.Toggle />
                    </div>
                </div>
            </Toast>
        )
    }
}

export default MeuToast