import React, { useReducer } from "react"
import { Modal } from "react_components/shared"
import { portalApiCall, PORTAL_PATH } from "shared/api"

import AddIcon from "@mui/icons-material/Add";
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";
import Grid from "@mui/material/Grid";
import Link from "@mui/material/Link";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

const createDevice = async ({
  localState, setLocalState, setState, fetchAll
}) => {
  setLocalState({working: true})
  await portalApiCall({
    collection: "devices",
    method: "POST",
    body: { mac: localState.mac },
    success: () => {
      // Perform a fetch on the DeviceManager to show the new record.
      fetchAll({ setState })

      // Set working to false and close the modal.
      setLocalState({ working: false, error: false, mac: "" })
      setState({ showNewDeviceModal: false })
    },
    error: () => {
      setLocalState({ working: false, error: true })
    },
  })
}

const NewDeviceModal = ({ state, setState, fetchAll }) => {
  const [localState, setLocalState] = useReducer(
    (state, newState) => ({ ...state, ...newState }),
    { working: false, error: false, mac: "" },
  )
  const handleChange = (e) => setLocalState({ mac: e.target.value })
  const handleClick = () => createDevice({
    localState, setLocalState, setState, fetchAll
  })

  return (
    <Modal
      open={state.showNewDeviceModal}
      onClose={() => { setState({showNewDeviceModal: false}) }}
    >
      <Typography variant="h6" component="h2" sx={{mb: "1em"}}>
        {__("Add Device")}
      </Typography>
      <Typography>
        {__(`
          Use this option if you wish to add access for a different device
          or a headless device such as a printer or game console. Enter the
          device's hardware identifier (MAC address) in the field and click
          the Add button below.
        `)}
      </Typography>
      <Grid
        container
        spacing={1}
        direction="row"
        justifyContent="center"
        alignItems="center"
        sx={{my: "2em"}}
      >
        <Grid item>
          <TextField
            label={__("MAC Address")}
            placeholder="00:00:00:00:00:00"
            variant="outlined"
            value={localState.mac}
            onChange={handleChange}
            error={localState.error}
          />
        </Grid>
        <Grid item>
          <Button
            startIcon={
              localState.working ? <CircularProgress size="1em" /> : <AddIcon />
            }
            onClick={handleClick}
            disabled={localState.working}
          >{__("Add Device")}</Button>
        </Grid>
      </Grid>
      <Typography>
        <Link href={`${PORTAL_PATH}/mac_info`}>
          {__("How do I find my MAC address?")}
        </Link>
      </Typography>
    </Modal>
  )
}

export default NewDeviceModal
