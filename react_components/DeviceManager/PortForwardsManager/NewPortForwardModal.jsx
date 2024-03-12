import React, { useReducer, useRef } from "react"
import { Modal } from "react_components/shared"
import { portalApiCall } from "shared/api"

import AddIcon from "@mui/icons-material/Add";
import Button from "@mui/material/Button";
import CircularProgress from "@mui/material/CircularProgress";
import FormControl from "@mui/material/FormControl";
import FormHelperText from "@mui/material/FormHelperText";
import Grid from "@mui/material/Grid";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

const createPortForward = async ({
  deviceId, formRef, formState, setFormState, setState, fetchAll
}) => {
  setFormState({ working: true })

  // Extract the form body.
  const { working, errors, ...form } = formState

  if (!formRef.current.reportValidity()) {
    setFormState({ working: false })
    return
  }

  await portalApiCall({
    collection: `devices/${deviceId}/port_forwards`,
    method: "POST",
    body: form,
    success: () => {
      // Perform a fetch to show the new record.
      fetchAll({ deviceId, setState })

      // Set working to false and close the modal.
      setFormState(initialFormState)
      setState({ showNewPortForwardModal: false })
    },
    error: ({ data }) => {
      setFormState({
        working: false, errors: (data ? data.errors : null) || {}
      })
    },
  })
}

const initialFormState = {
  working: false,
  name: "",
  external_ports: "",
  internal_ports: "",
  protocol: "tcp udp",
  errors: {},
}

const NewPortForwardModal = ({
  deviceId, state, setState, fetchAll, protocolValues
}) => {
  const [formState, setFormState] = useReducer(
    (state, newState) => ({ ...state, ...newState }), initialFormState
  )
  const formRef = useRef()
  const handleClose = () => setState({showNewPortForwardModal: false})
  const handleChange = (column) => {
    return (e) => setFormState({ [column]: e.target.value })
  }
  const handleSubmit = () => createPortForward({
    deviceId, formRef, formState, setFormState, setState, fetchAll
  })

  return (
    <Modal
      size="sm"
      open={state.showNewPortForwardModal}
      onClose={handleClose}
    >
      <Typography variant="h6" component="h2" sx={{mb: ".3em"}}>
        {__("New Port Forward")}
      </Typography>
      <form ref={formRef}>
        <Grid
          container
          spacing={3}
          direction="column"
        >
          <Grid item>
            <TextField
              fullWidth
              label={__("Name")}
              variant="standard"
              value={formState.name}
              onChange={handleChange("name")}
              error={!!formState.errors.name}
              helperText={formState.errors.name ? formState.errors.name[0] : ""}
              required
            />
          </Grid>
          <Grid item>
            <TextField
              fullWidth
              label={__("External Ports")}
              variant="standard"
              value={formState.external_ports}
              onChange={handleChange("external_ports")}
              error={!!formState.errors.external_ports}
              helperText={
                formState.errors.external_ports ?
                formState.errors.external_ports[0] : ""
              }
              required
            />
          </Grid>
          <Grid item>
            <FormControl fullWidth>
              <TextField
                label={__("Internal Ports")}
                variant="standard"
                value={formState.internal_ports}
                onChange={handleChange("internal_ports")}
                error={!!formState.errors.internal_ports}
                helperText={
                  formState.errors.internal_ports ?
                  formState.errors.internal_ports[0] : ""
                }
              />
            </FormControl>
          </Grid>
          <Grid item>
            <FormControl required>
              <InputLabel>{__("Protocol")}</InputLabel>
              <Select
                variant="standard"
                value={formState.protocol}
                onChange={handleChange("protocol")}
                error={!!formState.errors.protocol}
                sx={{ width: "10em" }}
                required
              >{
                protocolValues.map((p) => (
                  <MenuItem key={p} value={p}>{p}</MenuItem>
                ))
              }</Select>
              <FormHelperText>
                {
                  formState.errors.protocol ? formState.errors.protocol[0] : ""
                }
              </FormHelperText>
            </FormControl>
            <Button
              startIcon={
                formState.working ? <CircularProgress size="1em" /> : <AddIcon />
              }
              onClick={handleSubmit}
              sx={{ mt: ".3em", float: "right" }}
              disabled={formState.working}
            >{__("Create")}</Button>
          </Grid>
        </Grid>
      </form>
    </Modal>
  )
}

export default NewPortForwardModal
