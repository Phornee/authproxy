import unittest
from pathlib import Path

from homeservices import HomeServices


class Testing(unittest.TestCase):
    templates_path = "{}/templates".format(Path().absolute())
    static_path = "{}/static".format(Path().absolute())

    template_config_path = '{}/data/config-template.yml'.format(Path(__file__).parent)
    service = HomeServices(template_folder=templates_path,
                           static_folder=static_path,
                           template_config_path=template_config_path)
    client = service.getApp().test_client()

    points = [{'time': '2022-12-19T13:32:02.501231Z', 'tags': {'sensorid': '1'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:30:02.442527Z', 'tags': {'sensorid': '1'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:28:03.145696Z', 'tags': {'sensorid': '1'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:26:02.852427Z', 'tags': {'sensorid': '1'},
                                                      'fields': {'humidity': 53.4, 'temp': 20.2}},
              {'time': '2022-12-19T13:32:02.501231Z', 'tags': {'sensorid': '2'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:30:02.442527Z', 'tags': {'sensorid': '2'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:28:03.145696Z', 'tags': {'sensorid': '2'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:26:02.852427Z', 'tags': {'sensorid': '2'},
                                                      'fields': {'humidity': 53.4, 'temp': 20.2}},
              {'time': '2022-12-19T13:32:02.501231Z', 'tags': {'sensorid': '3'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:30:02.442527Z', 'tags': {'sensorid': '3'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:28:03.145696Z', 'tags': {'sensorid': '3'},
                                                      'fields': {'humidity': 53.3, 'temp': 20.3}},
              {'time': '2022-12-19T13:26:02.852427Z', 'tags': {'sensorid': '3'},
                                                      'fields': {'humidity': 53.4, 'temp': 20.2}}]
    service.conn.insert('DHT22', points)

    def test_index(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_alexaintent(self):
        response = self.client.get('/alexaintent')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/alexaintent?sensor=buhardilla')
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/alexaintent?sensor=unexisting')
        self.assertEqual(response.status_code, 404)

    def test_customsensor(self):
        response = self.client.get('/customsensor')
        self.assertEqual(response.status_code, 404)
        response = self.client.get('/customsensor?sensor=buhardilla')
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/customsensor?sensor=unexisting')
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
