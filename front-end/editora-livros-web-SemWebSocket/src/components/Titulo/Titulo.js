import React from "react";

export const Titulo = ({ texto }) => {
  return (
    <h className="text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
      {texto}
    </h>
  );
}