<?php

/*
 * Pin 26.7.6 a842fe48c21288d11a422cb944678e8eb308becf
 * Excerpt from FirmwareController.php setAction (L974-L1013).
 * Lab reimplements the FILTER_SANITIZE_URL foreach; this file is not executed.
 */

    /**
     * set firmware configuration options
     * @return array status
     */
    public function setAction()
    {
        $response = ['status' => 'failure'];

        if (!$this->request->isPost()) {
            return $response;
        }

        $values = $this->request->getPost(static::$internalModelName);

        foreach ($values as $key => &$value) {
            if ($key == 'plugins') {
                /* discards plugins on purpose for the time being */
                unset($values[$key]);
            } else {
                $value = filter_var($value, FILTER_SANITIZE_URL);
            }
        }

        $mdl = $this->getModel();
        $mdl->setNodes($values);

        $ret = $this->validate();
        if (!empty($ret['result'])) {
            $response['status_msg'] = array_values($ret['validations'] ?? [gettext('Unkown firmware validation error')]);
            return $response;
        }

        $response['status'] = 'ok';
        $this->save();

        $backend = new Backend();
        $backend->configdRun('firmware flush');
        $backend->configdRun('firmware reload');

        return $response;
    }
