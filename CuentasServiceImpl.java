
package com.app.bank.services.Impl;

import com.app.bank.models.entities.Transacciones;
import com.app.bank.models.entities.Usuarios;
import com.app.bank.repositories.TransaccionesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.app.bank.models.dto.CuentaRequestDTO;
import com.app.bank.models.dto.OperacionCuentaDTO;
import com.app.bank.models.dto.TransferirDTO;
import com.app.bank.models.entities.Cuentas;
import com.app.bank.repositories.CuentasRepository;
import com.app.bank.services.CuentasService;

import jakarta.transaction.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;



@Service
public class CuentasServiceImpl implements CuentasService{

    @Autowired
    private CuentasRepository cuentasRepository;

    @Autowired
    private TransaccionesRepository transaccionesRepository;

    @Override
    @Transactional
    public void transferir(TransferirDTO transferencia) {
        // Obtener el usuario autenticado
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Usuarios usuarioAutenticado = (Usuarios) auth.getPrincipal();

        // Obtener la cuenta de origen asociada al usuario autenticado
        Cuentas cuentaOrigen = cuentasRepository.findByUsuarioId(usuarioAutenticado.getId());

        // Verificar que el usuario tiene una cuenta
        if (cuentaOrigen == null) {
            throw new IllegalArgumentException("El usuario no tiene una cuenta asociada.");
        }

        // Obtener la cuenta de destino a partir del número de cuenta proporcionado
        Cuentas cuentaDestino = cuentasRepository.findByNumeroCuenta(transferencia.getCuentaDestino());

        // Verificar que la cuenta destino exista
        if (cuentaDestino == null) {
            throw new IllegalArgumentException("La cuenta destino no existe.");
        }

        // Verificar que el saldo de la cuenta de origen sea suficiente
        if (cuentaOrigen.getSaldo() < transferencia.getMonto()) {
            throw new IllegalArgumentException("Saldo insuficiente en la cuenta de origen.");
        }

        // Realizar la operación de transferencia
        double nuevoSaldoOrigen = cuentaOrigen.getSaldo() - transferencia.getMonto();
        double nuevoSaldoDestino = cuentaDestino.getSaldo() + transferencia.getMonto();

        cuentaOrigen.setSaldo(nuevoSaldoOrigen);
        cuentaDestino.setSaldo(nuevoSaldoDestino);

        // Guardar los cambios en ambas cuentas
        cuentasRepository.save(cuentaOrigen);
        cuentasRepository.save(cuentaDestino);

        Transacciones transaccion = new Transacciones();
        transaccion.setCuentaDestino(cuentaDestino);
        transaccion.setCuentaOrigen(cuentaOrigen);
        transaccion.setFecha(LocalDateTime.now());
        transaccion.setMonto(transferencia.getMonto());
        transaccionesRepository.save(transaccion);
    }


    @Override
    public void depositar(OperacionCuentaDTO monto) {
        // Obtener el usuario autenticado
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Usuarios usuarioAutenticado = (Usuarios) auth.getPrincipal();

        // Buscar la cuenta asociada al usuario autenticado
        Cuentas cuenta = cuentasRepository.findByUsuarioId(usuarioAutenticado.getId());

        // Verificar que el usuario tiene una cuenta
        if (cuenta == null) {
            throw new IllegalArgumentException("El usuario no tiene una cuenta asociada.");
        }

        // Realizar la operación de depósito
        double nuevoSaldo = cuenta.getSaldo() + monto.getMonto();
        cuenta.setSaldo(nuevoSaldo);

        cuentasRepository.save(cuenta);
    }

    @Override
    public void retirar(OperacionCuentaDTO monto) {
        // Obtener el usuario autenticado
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Usuarios usuarioAutenticado = (Usuarios) auth.getPrincipal();

        // Buscar la cuenta asociada al usuario autenticado
        Cuentas cuenta = cuentasRepository.findByUsuarioId(usuarioAutenticado.getId());

        // Verificar que el usuario tiene una cuenta
        if (cuenta == null) {
            throw new IllegalArgumentException("El usuario no tiene una cuenta asociada.");
        }

        // Verificar fondos suficientes
        if (cuenta.getSaldo() < monto.getMonto()) {
            throw new IllegalArgumentException("Saldo insuficiente");
        }

        // Realizar la operación de retiro
        double nuevoSaldo = cuenta.getSaldo() - monto.getMonto();
        cuenta.setSaldo(nuevoSaldo);

        cuentasRepository.save(cuenta);
    }

    @Override
    public Map<String, Double> getSaldo() {
        Map<String, Double> response = new HashMap<>();

        // Obtener el usuario autenticado
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Usuarios usuarioAutenticado = (Usuarios) auth.getPrincipal(); // Asumimos que se trata de un objeto Usuarios

        // Buscar la cuenta asociada al usuario autenticado
        Cuentas cuenta = cuentasRepository.findByUsuarioId(usuarioAutenticado.getId());

        // Verificar que el usuario tiene una cuenta
        if (cuenta == null) {
            throw new IllegalArgumentException("El usuario no tiene una cuenta asociada.");
        }

        response.put("saldo", cuenta.getSaldo());
        return response;
    }

    

    private void verificarPropietario(Cuentas cuenta) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Verificar que el principal sea una instancia de UserDetails
        if (auth.getPrincipal() instanceof UserDetails) {
            Usuarios usuarioAutenticado = (Usuarios) auth.getPrincipal(); // Aquí realizamos el cast

            if (cuenta.getUsuario().getId() != usuarioAutenticado.getId()) {
                throw new SecurityException("No está autorizado para realizar esta operación en esta cuenta");
            }
        } else {
            throw new SecurityException("Usuario no autenticado");
        }
    }


}
