import React, { useReducer } from "react"
import { Modal } from "react_components/shared"
import { portalApiCall, PORTAL_PATH } from "shared/api"

import Add from "@mui/icons-material/Add"
import Delete from "@mui/icons-material/Delete"
import Button from "@mui/material/Button"
import Grid from "@mui/material/Grid"
import Link from "@mui/material/Link"
import TextField from "@mui/material/TextField"
import Typography from "@mui/material/Typography"




const DhcpFixedHostModal = ({ setState, fetchAll, dhcpFixedHostModalState, setDhcpFixedHostModalState }) => {

  const [localState, setLocalState] = useReducer(
    (state, newState) => ({ ...state, ...newState }),
    { working: false, error: false, exception: null },
    )

    const handleClick = () => {
      const ip = dhcpFixedHostModalState.targetIp
      updateDhcpFixedHost({
        ip, setLocalState, setState, setDhcpFixedHostModalState, dhcpFixedHostModalState, fetchAll
      })
    }

    const handleDeleteClick = () => deleteDhcpFixedHost({
      setLocalState, setState, setDhcpFixedHostModalState, dhcpFixedHostModalState, fetchAll
    })

    const handleQuickCreateClick = () => {
      const ip = dhcpFixedHostModalState.dhcpFixedHostModalDeviceIp
      updateDhcpFixedHost({
        ip, setLocalState, setState, setDhcpFixedHostModalState, dhcpFixedHostModalState, fetchAll
      })
    }

  return (
    <Modal
      open={dhcpFixedHostModalState.showDhcpFixedHostModal}
      onClose={() => { blankModalStateAttributes({ setDhcpFixedHostModalState }) }}
    >
      <Typography variant="h6" component="h2" sx={{ mb: "1em" }}>
        {__("Set Device's DHCP Reservation")}
      </Typography>
      <Typography>
        {__(`
          Use this option if you want this device to be associated with a
          reserved IP address so that every time it connects to your network it
          will be assigned the same IP address. If your device does not have a
          reserved host, your gateway will give this device the next available
          IP address from the pool of available IP addresses each time it
          connects.
        `)}
      </Typography>
      <Grid
        container
        spacing={1}
        direction="row"
        justifyContent="center"
        alignItems="center"
        sx={{ my: "2em" }}
      >
        <Grid item>
          <TextField
            label={__("Reserved IP")}
            placeholder={dhcpFixedHostModalState.dhcpFixedHostModalDeviceIp}
            variant="outlined"
            value={dhcpFixedHostModalState.targetIp}
            onChange={e =>  setDhcpFixedHostModalState({targetIp: e.target.value})}
            error={localState.error}
          />
        </Grid>
        <Grid item>
          <Grid
            container
            spacing={1}
            direction="column"
            justifyContent="center"
            alignItems="center"
            sx={{ my: "2em" }}
          >
            <Grid item>
              <Button
                startIcon={
                  localState.working ? <CircularProgress size="1em" /> : <Add />
                }
                onClick={handleClick}
                disabled={localState.working}
              >{__("Set DHCP Reservation")}</Button>
            </Grid>
            <Grid item>
              {
                dhcpFixedHostModalState.dhcpFixedHostModalFixedHostId ?
                  <Button
                    startIcon={
                      localState.working ? <CircularProgress size="1em" /> : <Delete />
                    }
                    onClick={handleDeleteClick}
                    disabled={localState.working}
                  >{__("Delete DHCP Reservation")}</Button>
                  :
                  <Button
                    startIcon={
                      localState.working ? <CircularProgress size="1em" /> : <Add />
                    }
                    onClick={handleQuickCreateClick}
                    disabled={localState.working}
                  >
                    {__(`Quick Create From Current IP ${dhcpFixedHostModalState.dhcpFixedHostModalDeviceIp}`)}
                  </Button>
              }
            </Grid>
          </Grid>
        </Grid>
      </Grid>
      <Grid
        container
        spacing={1}
        direction="row"
        justifyContent="center"
        alignItems="center"
        sx={{ my: "2em" }}
      >
        <Typography>
          {localState.error ? __(`${localState.exception}`) : null}
        </Typography>
      </Grid>
      <Typography>
        <Link href={`${PORTAL_PATH}/dhcp_fixed_host_info`}>
          {__("Why would I want to give my device a reserved host?")}
        </Link>
      </Typography>
    </Modal>
  )
}

const ip6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/

const ip4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/

const blankModalStateAttributes = ({ setDhcpFixedHostModalState }) => {
  setDhcpFixedHostModalState({
    dhcpFixedHostModalDeviceId: null,
    dhcpFixedHostModalDeviceIp: null,
    dhcpFixedHostModalFixedHostIp: null,
    dhcpFixedHostModalFixedHostId: null,
    showDhcpFixedHostModal: false
  })
}

const updateDhcpFixedHost = async ({
  ip, setLocalState, setState, setDhcpFixedHostModalState, dhcpFixedHostModalState, fetchAll
}) => {

  if (!ip.match(ip6Regex) && !ip.match(ip4Regex)) {
    setLocalState({ working: false, error: true, exception: `${ip} does not look like a valid address.` })
    return
  }

  let method, id, body

  if (dhcpFixedHostModalState.dhcpFixedHostModalFixedHostIp) {
    method = "PATCH"
    id = dhcpFixedHostModalState.dhcpFixedHostModalFixedHostId
  } else {
    method = "POST"
  }

  body = {
    "device_id": dhcpFixedHostModalState.dhcpFixedHostModalDeviceId,
    name: ip,
    ip
  }

  await portalApiCall({
    collection: `devices/${dhcpFixedHostModalState.dhcpFixedHostModalDeviceId}/dhcp_fixed_host`,
    record_id: id,
    method: method,
    body: body,
    success: () => {
      fetchAll({ setState })
      setLocalState({ working: false, error: false, exception: null })
      blankModalStateAttributes({ setState, setDhcpFixedHostModalState })
    },
    error: (resp) => {
      switch (resp.status) {
        case 500: setLocalState({ exception: "An Unknown Exception Occurred" }); break
        default: setLocalState({ exception: resp.data.exception })
      }
      setLocalState({ working: false, error: true })
    }
  })
}

const deleteDhcpFixedHost = async ({
  setLocalState, setState, setDhcpFixedHostModalState, dhcpFixedHostModalState, fetchAll
}) => {

  await portalApiCall({
    collection: `devices/${dhcpFixedHostModalState.dhcpFixedHostModalDeviceId}/dhcp_fixed_host`,
    record_id: dhcpFixedHostModalState.dhcpFixedHostModalFixedHostId,
    method: "DELETE",
    success: () => {
      fetchAll({ setState })
      setLocalState({ working: false, error: false, exception: null })
      blankModalStateAttributes({ setState, setDhcpFixedHostModalState })
    },
    error: (resp) => {
      setLocalState({ working: false, error: true, exception: resp.data.exception })
    }
  })

}

export default DhcpFixedHostModal
